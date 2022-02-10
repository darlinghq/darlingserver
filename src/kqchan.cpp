#include <darlingserver/kqchan.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/thread.hpp>
#include <darlingserver/logging.hpp>

#include <sys/socket.h>
#include <fcntl.h>
#include <atomic>

static DarlingServer::Log kqchanMachPortLog("kqchan:mach_port");
static std::atomic_uint64_t kqchanDebugIDCounter = 0;

DarlingServer::Kqchan::Kqchan() {
	_debugID = kqchanDebugIDCounter++;
};
DarlingServer::Kqchan::~Kqchan() {};

DarlingServer::Kqchan::MachPort::MachPort(std::shared_ptr<Process> process, uint32_t port, uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags):
	_process(process),
	_port(port),
	_receiveBuffer(receiveBuffer),
	_receiveBufferSize(receiveBufferSize),
	_savedFilterFlags(savedFilterFlags)
{
	kqchanMachPortLog.debug() << "Constructing Mach port kqchan with ID " << _debugID << kqchanMachPortLog.endLog;
	kqchanMachPortLog.debug() << kqchanMachPortLog.endLog;
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

int DarlingServer::Kqchan::MachPort::setup() {
	int fds[2];

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

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) < 0) {
		int ret = errno;
		kqchanMachPortLog.debug() << "Failed to create socket pair" << kqchanMachPortLog.endLog;
		throw std::system_error(ret, std::generic_category());
	}

	// we'll keep fds[0] and give fds[1] away
	_socket = std::make_shared<FD>(fds[0]);

	kqchanMachPortLog.debug() << _debugID << ": Keeping socket " << fds[0] << " and giving away " << fds[1] << kqchanMachPortLog.endLog;

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

	std::weak_ptr<MachPort> weakThis = shared_from_this();

	_outbox.setMessageArrivalNotificationCallback([weakThis]() {
		auto self = weakThis.lock();

		if (!self) {
			return;
		}

		std::unique_lock lock(self->_sendingMutex);

		kqchanMachPortLog.debug() << self->_debugID << ": Got messages to send, attempting to send them" << kqchanMachPortLog.endLog;

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

		kqchanMachPortLog.debug() << self->_debugID << ": Got event(s) on socket: " << static_cast<uint64_t>(event) << kqchanMachPortLog.endLog;

		if (static_cast<uint64_t>(event & Monitor::Event::HangUp) != 0) {
			// socket hangup (peer closed their socket)

			kqchanMachPortLog.debug() << self->_debugID << ": Peer hung up their socket; cleaning up monitor and kqchan" << kqchanMachPortLog.endLog;

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

			kqchanMachPortLog.debug() << self->_debugID << ": socket has pending incoming messages" << kqchanMachPortLog.endLog;

			// receive them all
			while (self->_inbox.receiveMany(self->_socket->fd()));

			// process the messages
			while (auto msg = self->_inbox.pop()) {
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

						self->_modify(modify->receive_buffer, modify->receive_buffer_size, modify->saved_filter_flags, modify->header.tid);
					} break;

					case dserver_kqchan_msgnum_mach_port_read: {
						if (msg->data().size() < sizeof(dserver_kqchan_call_mach_port_read_t)) {
							throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_mach_port_read");
						}

						auto read = reinterpret_cast<dserver_kqchan_call_mach_port_read*>(callhdr);

						self->_read(read->default_buffer, read->default_buffer_size, read->header.tid);
					} break;

					default:
						throw std::invalid_argument("Unknown/invalid kqchan msgnum");
				}
			}
		}

		if (static_cast<uint64_t>(event & Monitor::Event::Writable) != 0) {
			// we can now send messages again;
			// send as many messages as we can

			std::unique_lock lock(self->_sendingMutex);

			kqchanMachPortLog.debug() << self->_debugID << ": socket is now writable; sending all pending outgoing messages" << kqchanMachPortLog.endLog;
			do {
				self->_canSend = self->_outbox.sendMany(self->_socket->fd());
			} while (self->_canSend  && !self->_outbox.empty());
		}
	});

	DarlingServer::Server::sharedInstance().addMonitor(_monitor);

	if (dtape_kqchan_mach_port_has_events(_dtapeKqchan)) {
		// if we already have an event, notify the kqchan;
		// this will simply enqueue a message to be sent to the peer.
		// since our libkqueue filter uses level-triggered epoll,
		// our peer will immediately see there's an event available when it starts waiting.
		_notify();
	}

	return fds[1];
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
		dtape_kqchan_mach_port_fill(self->_dtapeKqchan, reply, defaultBuffer, defaultBufferSize);
		Thread::currentThread()->impersonate(nullptr);

		self->_outbox.push(std::move(msg));
	});
};

void DarlingServer::Kqchan::MachPort::_notify() {
	std::unique_lock lock(_notificationMutex);

	kqchanMachPortLog.debug() << _debugID << ": received notification from duct-taped Mach port kqchan" << kqchanMachPortLog.endLog;

	if (!_canSendNotification) {
		// we've already sent our peer a notification that they haven't acknowledged yet;
		// let's not send another and needlessly clog up the socket
		kqchanMachPortLog.debug() << _debugID << ": earlier notification has not yet been acknowledged; not sending another notification" << kqchanMachPortLog.endLog;
		return;
	}

	kqchanMachPortLog.debug() << _debugID << ": sending notification" << kqchanMachPortLog.endLog;

	// now that we're sending the notification, we shouldn't send another one until our peer acknowledges this one
	_canSendNotification = false;

	Message msg(sizeof(dserver_kqchan_call_notification_t), 0);

	auto notification = reinterpret_cast<dserver_kqchan_call_notification_t*>(msg.data().data());
	notification->header.number = dserver_kqchan_msgnum_notification;
	notification->header.pid = 0;
	notification->header.tid = 0;

	_outbox.push(std::move(msg));
};
