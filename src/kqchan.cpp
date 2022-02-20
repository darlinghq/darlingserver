#include <darlingserver/kqchan.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/thread.hpp>
#include <darlingserver/logging.hpp>

#include <sys/socket.h>
#include <fcntl.h>
#include <atomic>

static DarlingServer::Log kqchanLog("kqchan");
static DarlingServer::Log kqchanMachPortLog("kqchan:mach_port");
static DarlingServer::Log kqchanProcLog("kqchan:proc");
static std::atomic_uint64_t kqchanDebugIDCounter = 0;

//
// base class
//

DarlingServer::Kqchan::Kqchan(std::shared_ptr<DarlingServer::Process> process):
	_debugID(kqchanDebugIDCounter++),
	_process(process)
{
	kqchanLog.debug() << "Constructing kqchan with ID " << _debugID << kqchanLog.endLog;
};

DarlingServer::Kqchan::~Kqchan() {
	kqchanLog.debug() << "Destroying kqchan with ID " << _debugID << kqchanLog.endLog;
};

uintptr_t DarlingServer::Kqchan::_idForProcess() const {
	throw std::runtime_error("must be overridden in derived class");
};

void DarlingServer::Kqchan::_processMessages() {
	throw std::runtime_error("must be overridden in derived class");
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::sharedFromRoot() {
	throw std::runtime_error("must be overridden in derived class");
};

int DarlingServer::Kqchan::setup() {
	int fds[2];

	kqchanLog.debug() << "Setting up kqchan with ID " << _debugID << kqchanLog.endLog;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) < 0) {
		int ret = errno;
		kqchanLog.debug() << "Failed to create socket pair" << kqchanLog.endLog;
		throw std::system_error(ret, std::generic_category());
	}

	// we'll keep fds[0] and give fds[1] away
	_socket = std::make_shared<FD>(fds[0]);

	kqchanLog.debug() << _debugID << ": Keeping socket " << fds[0] << " and giving away " << fds[1] << kqchanLog.endLog;

	// set O_NONBLOCK on our socket
	int flags = fcntl(_socket->fd(), F_GETFL);
	if (flags < 0) {
		int ret = errno;
		throw std::system_error(ret, std::generic_category());
	}
	if (fcntl(_socket->fd(), F_SETFL, flags | O_NONBLOCK) < 0) {
		int ret = errno;
		throw std::system_error(ret, std::generic_category());
	}

	std::weak_ptr<Kqchan> weakThis = sharedFromRoot();

	_outbox.setMessageArrivalNotificationCallback([weakThis]() {
		auto self = weakThis.lock();

		if (!self) {
			return;
		}

		std::unique_lock lock(self->_sendingMutex);

		kqchanLog.debug() << self->_debugID << ": Got messages to send, attempting to send them" << kqchanLog.endLog;

		// we probably won't be sending very many messages at once;
		// we can send all the messages in the same context that they were pushed
		do {
			self->_canSend = self->_outbox.sendMany(self->_socket->fd());
		} while (self->_canSend && !self->_outbox.empty());
	});

	_monitor = std::make_shared<Monitor>(_socket, Monitor::Event::Readable | Monitor::Event::Writable | Monitor::Event::HangUp, true, false, [weakThis](std::shared_ptr<Monitor> monitor, Monitor::Event event) {
		auto self = weakThis.lock();

		if (!self) {
			return;
		}

		kqchanLog.debug() << self->_debugID << ": Got event(s) on socket: " << static_cast<uint64_t>(event) << kqchanLog.endLog;

		if (static_cast<uint64_t>(event & Monitor::Event::HangUp) != 0) {
			// socket hangup (peer closed their socket)

			kqchanLog.debug() << self->_debugID << ": Peer hung up their socket; cleaning up monitor and kqchan" << kqchanLog.endLog;

			// stop monitoring the socket (we're not gonna get any more events out of it)
			Server::sharedInstance().removeMonitor(monitor);

			// and unregister ourselves from the process (if it still exists)
			// (which means the instance should be freed once we return)
			if (auto process = self->_process.lock()) {
				process->unregisterKqchan(self);
			}

			// no need to process any other events that may have occurred
			return;
		}

		if (static_cast<uint64_t>(event & Monitor::Event::Readable) != 0) {
			// incoming messages

			kqchanLog.debug() << self->_debugID << ": socket has pending incoming messages" << kqchanLog.endLog;

			// receive them all
			while (self->_inbox.receiveMany(self->_socket->fd()));

			// process the messages
			self->_processMessages();
		}

		if (static_cast<uint64_t>(event & Monitor::Event::Writable) != 0) {
			// we can now send messages again;
			// send as many messages as we can

			std::unique_lock lock(self->_sendingMutex);

			kqchanLog.debug() << self->_debugID << ": socket is now writable; sending all pending outgoing messages" << kqchanLog.endLog;
			do {
				self->_canSend = self->_outbox.sendMany(self->_socket->fd());
			} while (self->_canSend  && !self->_outbox.empty());
		}
	});

	DarlingServer::Server::sharedInstance().addMonitor(_monitor);

	return fds[1];
};

void DarlingServer::Kqchan::_sendNotification() {
	std::unique_lock lock(_notificationMutex);

	kqchanLog.debug() << _debugID << ": received request to send notification" << kqchanLog.endLog;

	if (!_canSendNotification) {
		// we've already sent our peer a notification that they haven't acknowledged yet;
		// let's not send another and needlessly clog up the socket
		kqchanLog.debug() << _debugID << ": earlier notification has not yet been acknowledged; not sending another notification" << kqchanLog.endLog;
		return;
	}

	kqchanLog.debug() << _debugID << ": sending notification" << kqchanLog.endLog;

	// now that we're sending the notification, we shouldn't send another one until our peer acknowledges this one
	_canSendNotification = false;

	Message msg(sizeof(dserver_kqchan_call_notification_t), 0);

	auto notification = reinterpret_cast<dserver_kqchan_call_notification_t*>(msg.data().data());
	notification->header.number = dserver_kqchan_msgnum_notification;
	notification->header.pid = 0;
	notification->header.tid = 0;

	_outbox.push(std::move(msg));
};

//
// mach port
//

DarlingServer::Kqchan::MachPort::MachPort(std::shared_ptr<DarlingServer::Process> process, uint32_t port, uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags):
	Kqchan(process),
	_port(port),
	_receiveBuffer(receiveBuffer),
	_receiveBufferSize(receiveBufferSize),
	_savedFilterFlags(savedFilterFlags)
{
	kqchanMachPortLog.debug() << "Constructing Mach port kqchan with ID " << _debugID << kqchanMachPortLog.endLog;
};

DarlingServer::Kqchan::MachPort::~MachPort() {
	kqchanMachPortLog.debug() << "Destroying Mach port kqchan with ID " << _debugID << kqchanMachPortLog.endLog;

	if (_dtapeKqchan) {
		auto kqchan = _dtapeKqchan;

		// disable notifications so that `this` won't be used after we're destroyed
		dtape_kqchan_mach_port_disable_notifications(kqchan);

		// and schedule the duct-taped kqchan to be destroyed on a microthread
		auto debugID = _debugID;
		Thread::kernelAsync([=]() {
			kqchanMachPortLog.debug() << "Destroying duct-taped Mach port kqchan with ID " << debugID << kqchanMachPortLog.endLog;
			dtape_kqchan_mach_port_destroy(kqchan);
		});
	}
};

uintptr_t DarlingServer::Kqchan::MachPort::_idForProcess() const {
	return reinterpret_cast<uintptr_t>(this);
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::MachPort::sharedFromRoot() {
	return shared_from_this();
};

int DarlingServer::Kqchan::MachPort::setup() {
	kqchanMachPortLog.debug() << "Setting up Mach port kqchan with ID " << _debugID << kqchanMachPortLog.endLog;

	// NOTE: the duct-taped kqchan will never notify us after we die
	//       since we disable notifications upon destruction,
	//       so using `this` here is safe
	_dtapeKqchan = dtape_kqchan_mach_port_create(_port, _receiveBuffer, _receiveBufferSize, _savedFilterFlags, [](void* context) {
		auto self = reinterpret_cast<MachPort*>(context);
		self->_notify();
	}, this);
	if (!_dtapeKqchan) {
		kqchanMachPortLog.debug() << "Failed to create duct-taped Mach port kqchan with ID " << _debugID << " for port " << _port << kqchanMachPortLog.endLog;
		throw std::system_error(ESRCH, std::generic_category());
	}

	int fd = Kqchan::setup();

	if (dtape_kqchan_mach_port_has_events(_dtapeKqchan)) {
		// if we already have an event, notify the kqchan;
		// this will simply enqueue a message to be sent to the peer.
		// since our libkqueue filter uses level-triggered epoll,
		// our peer will immediately see there's an event available when it starts waiting.
		_notify();
	}

	return fd;
};

void DarlingServer::Kqchan::MachPort::_processMessages() {
	while (auto msg = _inbox.pop()) {
		if (msg->data().size() < sizeof(dserver_kqchan_callhdr_t)) {
			throw std::invalid_argument("Message buffer was too small for kqchan call header");
		}

		auto callhdr = reinterpret_cast<dserver_kqchan_callhdr_t*>(msg->data().data());

		switch (callhdr->number) {
			case dserver_kqchan_msgnum_mach_port_modify: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_mach_port_modify_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_msgnum_mach_port_modify");
				}

				auto modify = reinterpret_cast<dserver_kqchan_call_mach_port_modify_t*>(callhdr);

				_modify(modify->receive_buffer, modify->receive_buffer_size, modify->saved_filter_flags, modify->header.tid);
			} break;

			case dserver_kqchan_msgnum_mach_port_read: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_mach_port_read_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_mach_port_read");
				}

				auto read = reinterpret_cast<dserver_kqchan_call_mach_port_read_t*>(callhdr);

				_read(read->default_buffer, read->default_buffer_size, read->header.tid);
			} break;

			default:
				throw std::invalid_argument("Unknown/invalid kqchan msgnum");
		}
	}
};

void DarlingServer::Kqchan::MachPort::_modify(uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags, pid_t nstid) {
	kqchanMachPortLog.debug() << _debugID << ": Received modification request with {receiveBuffer=" << receiveBuffer << ",receiveBufferSize=" << receiveBufferSize << ",savedFilterFlags=" << savedFilterFlags << "}" << kqchanMachPortLog.endLog;

	auto maybeThread = threadRegistry().lookupEntryByNSID(nstid);

	if (!maybeThread) {
		throw std::runtime_error("No thread for Mach port kqchan modification?");
	}

	auto thread = *maybeThread;

	auto self = shared_from_this();
	Thread::kernelAsync([=]() {
		kqchanMachPortLog.debug() << self->_debugID << ": Handling modification request in microthread" << kqchanMachPortLog.endLog;

		Thread::currentThread()->impersonate(thread);
		dtape_kqchan_mach_port_modify(self->_dtapeKqchan, receiveBuffer, receiveBufferSize, savedFilterFlags);
		Thread::currentThread()->impersonate(nullptr);

		Message msg(sizeof(dserver_kqchan_reply_mach_port_modify_t), 0);

		auto reply = reinterpret_cast<dserver_kqchan_reply_mach_port_modify_t*>(msg.data().data());

		reply->header.number = dserver_kqchan_msgnum_mach_port_modify;
		reply->header.code = 0;

		kqchanMachPortLog.debug() << _debugID << ": Sending modification reply/acknowledgement" << kqchanMachPortLog.endLog;

		self->_outbox.push(std::move(msg));
	});
};

void DarlingServer::Kqchan::MachPort::_read(uint64_t defaultBuffer, uint64_t defaultBufferSize, pid_t nstid) {
	kqchanMachPortLog.debug() << _debugID << ": received read request with {defaultBuffer=" << defaultBuffer << ",defaultBufferSize=" << defaultBufferSize << "}" << kqchanMachPortLog.endLog;

	{
		// our peer has acknowledged our notification by asking for the pending messages;
		// we can now send a notification again if we receive more data
		std::unique_lock lock(_notificationMutex);
		kqchanMachPortLog.debug() << _debugID << ": received acknowledgement (implicitly via read); notifications may now be sent" << kqchanMachPortLog.endLog;
		_canSendNotification = true;
	}

	auto maybeThread = threadRegistry().lookupEntryByNSID(nstid);

	if (!maybeThread) {
		throw std::runtime_error("No thread for Mach port kqchan read?");
	}

	auto thread = *maybeThread;

	auto self = shared_from_this();
	Thread::kernelAsync([=]() {
		Message msg(sizeof(dserver_kqchan_reply_mach_port_read_t), 0);

		kqchanMachPortLog.debug() << self->_debugID << ": handling read request in microthread" << kqchanMachPortLog.endLog;

		auto reply = reinterpret_cast<dserver_kqchan_reply_mach_port_read_t*>(msg.data().data());

		reply->header.code = 0;
		reply->header.number = dserver_kqchan_msgnum_mach_port_read;

		Thread::currentThread()->impersonate(thread);
		if (!dtape_kqchan_mach_port_fill(self->_dtapeKqchan, reply, defaultBuffer, defaultBufferSize)) {
			reply->header.code = 0xdead;
		}
		Thread::currentThread()->impersonate(nullptr);

		self->_outbox.push(std::move(msg));
	});
};

void DarlingServer::Kqchan::MachPort::_notify() {
	_sendNotification();
};

//
// process
//
// TODO: NOTE_REAP and NOTE_SIGNAL
//

DarlingServer::Kqchan::Process::Process(std::shared_ptr<DarlingServer::Process> process, pid_t nspid, uint32_t flags):
	Kqchan(process),
	_nspid(nspid),
	_flags(flags)
{
	kqchanProcLog.debug() << "Constructing process kqchan with ID " << _debugID << kqchanProcLog.endLog;
};

DarlingServer::Kqchan::Process::~Process() {
	kqchanProcLog.debug() << "Destroying process kqchan with ID " << _debugID << kqchanProcLog.endLog;

	if (auto targetProcess = _targetProcess.lock()) {
		targetProcess->unregisterListeningKqchan(_idForProcess());
	}
};

uintptr_t DarlingServer::Kqchan::Process::_idForProcess() const {
	return reinterpret_cast<uintptr_t>(this);
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::Process::sharedFromRoot() {
	return shared_from_this();
};

int DarlingServer::Kqchan::Process::setup() {
	kqchanProcLog.debug() << "Setting up process kqchan with ID " << _debugID << kqchanProcLog.endLog;

	auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_nspid);
	if (!maybeTargetProcess) {
		kqchanProcLog.debug() << "Failed to create process kqchan with ID " << _debugID << " for PID " << _nspid << kqchanProcLog.endLog;
		throw std::system_error(ESRCH, std::generic_category());
	}

	auto targetProcess = *maybeTargetProcess;

	_targetProcess = targetProcess;

	int fd = Kqchan::setup();

	{
		std::unique_lock lock(_mutex);
		if (!_attached) {
			targetProcess->registerListeningKqchan(shared_from_this());
			_attached = true;
		}
		if (!_events.empty()) {
			_sendNotification();
		}
	}

	return fd;
};

void DarlingServer::Kqchan::Process::_processMessages() {
	while (auto msg = _inbox.pop()) {
		if (msg->data().size() < sizeof(dserver_kqchan_callhdr_t)) {
			throw std::invalid_argument("Message buffer was too small for kqchan call header");
		}

		auto callhdr = reinterpret_cast<dserver_kqchan_callhdr_t*>(msg->data().data());

		switch (callhdr->number) {
			case dserver_kqchan_msgnum_proc_modify: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_proc_modify_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_proc_modify_");
				}

				auto modify = reinterpret_cast<dserver_kqchan_call_proc_modify_t*>(callhdr);

				_modify(modify->flags);
			} break;

			case dserver_kqchan_msgnum_proc_read: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_proc_read_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_proc_read");
				}

				auto read = reinterpret_cast<dserver_kqchan_call_proc_read_t*>(callhdr);

				_read();
			} break;

			default:
				throw std::invalid_argument("Unknown/invalid kqchan msgnum");
		}
	}
};

void DarlingServer::Kqchan::Process::_modify(uint32_t flags) {
	std::unique_lock lock(_mutex);

	_flags = flags;

	Message msg(sizeof(dserver_kqchan_reply_proc_modify_t), 0);

	auto reply = reinterpret_cast<dserver_kqchan_reply_proc_modify_t*>(msg.data().data());

	reply->header.number = dserver_kqchan_msgnum_proc_modify;
	reply->header.code = 0;

	kqchanProcLog.debug() << _debugID << ": Sending modification reply/acknowledgement" << kqchanProcLog.endLog;

	_outbox.push(std::move(msg));
};

void DarlingServer::Kqchan::Process::_read() {
	auto listeningProcess = _process.lock();

	if (!listeningProcess) {
		// if the listening process is dead, log it and ignore the request (no one's listening for the reply anyways)
		kqchanProcLog.warning() << _debugID << ": received read request after listening process died" << kqchanProcLog.endLog;
		return;
	}

	kqchanProcLog.debug() << _debugID << ": received read request" << kqchanProcLog.endLog;

	{
		// our peer has acknowledged our notification by asking for the pending messages;
		// we can now send a notification again if we receive more data
		std::unique_lock lock(_notificationMutex);
		kqchanProcLog.debug() << _debugID << ": received acknowledgement (implicitly via read); notifications may now be sent" << kqchanProcLog.endLog;
		_canSendNotification = true;
	}

	std::unique_lock lock(_mutex);
	Message msg(sizeof(dserver_kqchan_reply_proc_read_t), 0);
	auto reply = reinterpret_cast<dserver_kqchan_reply_proc_read_t*>(msg.data().data());

	reply->header.number = dserver_kqchan_msgnum_proc_read;
	reply->header.code = 0;
	reply->data = 0;
	reply->fflags = 0;

	while (true) {
		if (_events.empty()) {
			// if we don't have any events, tell our peer
			kqchanProcLog.debug() << _debugID << ": no events to read" << kqchanProcLog.endLog;

			reply->header.code = 0xdead;
			break;
		} else {
			auto event = std::move(_events.front());
			_events.pop_front();

			reply->data = event.data;
			reply->fflags = event.events & _flags;

			if (reply->fflags == 0) {
				// if this event contains no events that the user is interested in, drop it
				kqchanProcLog.debug() << _debugID << ": event does not contain any events the user is interested in; dropping event" << kqchanProcLog.endLog;
				continue;
			}

			if (_flags & NOTE_TRACK) {
				if (event.newKqchan) {
					auto savedFlags = _flags;

					// drop the lock; we don't need it to set up the new kqchan
					lock.unlock();

					try {
						FD newKqchanSocket(event.newKqchan->setup());

						// no errors SHOULD be thrown from this point forward

						// give the new kqchan the most recent flags we have
						{
							std::unique_lock lock(event.newKqchan->_mutex);
							event.newKqchan->_flags = savedFlags;
						}

						listeningProcess->registerKqchan(event.newKqchan);
						msg.pushDescriptor(newKqchanSocket.extract());

						kqchanProcLog.debug() << _debugID << ": new process kqchan (with ID " << event.newKqchan->_debugID << ") setup for child process and being returned" << kqchanProcLog.endLog;
					} catch (...) {
						kqchanProcLog.error() << _debugID << ": failed to setup new kqchan for child process" << kqchanProcLog.endLog;
						reply->fflags |= NOTE_TRACKERR;
					}

					// reacquire the lock; we need to check `_events` before we exit
					lock.lock();
				} else if (event.events & NOTE_FORK) {
					kqchanProcLog.error() << _debugID << ": read NOTE_FORK event and user has requested NOTE_TRACK, but no new kqchan was associated with event" << kqchanProcLog.endLog;
					reply->fflags |= NOTE_TRACKERR;
				}
			} else if (event.newKqchan) {
				kqchanProcLog.info() << _debugID << ": event contains new kqchan, but user has not requested NOTE_TRACK; dropping new kqchan" << kqchanProcLog.endLog;
			}

			break;
		}
	}

	_outbox.push(std::move(msg));

	// if we have more events ready, tell our peer
	if (!_events.empty()) {
		_sendNotification();
	}
};

void DarlingServer::Kqchan::Process::_notify(uint32_t event, int64_t data) {
	Event newEvent;

	kqchanProcLog.debug() << _debugID << ": notified with {event=" << event << ",data=" << data << "}" << kqchanProcLog.endLog;

	newEvent.data = data;
	newEvent.events = event;
	newEvent.newKqchan = nullptr;

	if (event == NOTE_FORK) {
		// NOTE: we always setup a new kqchan regardless of whether or not the user has currently requested NOTE_TRACK or not,
		//       in case the user does have NOTE_TRACK when reading the event.

		auto listeningProcess = _process.lock();

		if (!listeningProcess) {
			return;
		}

		auto maybeChild = processRegistry().lookupEntryByNSID(data & NOTE_PDATAMASK);

		if (!maybeChild) {
			kqchanProcLog.debug() << _debugID << ": notified with NOTE_FORK (and wanted NOTE_TRACK), but couldn't find child" << kqchanProcLog.endLog;
		} else {
			auto child = *maybeChild;

			auto newKqchan = std::make_shared<Process>(listeningProcess, data & NOTE_PDATAMASK, _flags);

			child->registerListeningKqchan(newKqchan);
			newKqchan->_targetProcess = child;
			newKqchan->_attached = true;

			auto childParent = child->parentProcess();

			newKqchan->_notify(NOTE_CHILD, (childParent ? childParent->nsid() : 0) & NOTE_PDATAMASK);

			newEvent.newKqchan = newKqchan;
		}
	}

	{
		std::unique_lock lock(_mutex);
		_events.push_back(std::move(newEvent));
		if (_socket) {
			_sendNotification();
		}
	}
};
