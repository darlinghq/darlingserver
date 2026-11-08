/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE 1
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <sys/uio.h>

#include <darlingserver/logging.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/config.hpp>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <darlingserver/kqchan.hpp>
#include <darlingserver/system-config.hpp>
#include <darlingserver/platform-identity.hpp>
#include <darlingserver/code-signing.hpp>
#include <darlingserver/trust-store.hpp>
#include <darling-config.h>
#include <kern/cs_blobs.h>
#include <limits.h>
#include <list>
#include <map>
#include <mutex>

static DarlingServer::Log callLog("calls");

DarlingServer::Log DarlingServer::Call::rpcReplyLog("replies");

std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage(Message&& requestMessage) {
	if (requestMessage.data().size() < sizeof(dserver_rpc_callhdr_t)) {
		throw std::invalid_argument("Message buffer was too small for call header");
	}

	dserver_rpc_callhdr_t* header = reinterpret_cast<dserver_rpc_callhdr_t*>(requestMessage.data().data());
	std::shared_ptr<Call> result = nullptr;
	std::shared_ptr<Process> process = nullptr;
	std::shared_ptr<Thread> thread = nullptr;

	// first, make sure we know this call number
	switch (header->number) {
		case dserver_callnum_s2c:
		case dserver_callnum_push_reply:
		DSERVER_VALID_CALLNUM_CASES
			break;

		default:
			throw std::invalid_argument("Invalid call number");
	}

	static const uid_t serverUid = getuid();

	if (requestMessage.uid() != serverUid) {
		throw std::runtime_error("System-reported message UID != darlingserver UID");
	}

	if ((header->number & DSERVER_CALL_UNMANAGED_FLAG) == 0) {
		// now let's lookup (and possibly create) the process and thread making this call
		process = processRegistry().registerIfAbsent(header->pid, [&]() {
			std::shared_ptr<Process> tmp = nullptr;

			int lifetimePipe = -1;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				if (checkinCall->body.lifetime_listener_pipe != -1) {
					lifetimePipe = requestMessage.extractDescriptorAtIndex(checkinCall->body.lifetime_listener_pipe);
					checkinCall->body.lifetime_listener_pipe = -1;
				}
			}

			try {
				tmp = std::make_shared<Process>(requestMessage.pid(), header->pid, static_cast<Process::Architecture>(header->architecture), lifetimePipe);
			} catch (std::system_error e) {
				return tmp;
			}

			Server::sharedInstance().monitorProcess(tmp);
			return tmp;
		});

		if (!process) {
			callLog.error() << "Received call from non-existent process?" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		// checked before thread registration so a rejected message cannot change a thread's reply address
		if (process->id() != requestMessage.pid()) {
			throw std::runtime_error("System-reported message PID != darlingserver-recorded PID");
		}

		thread = threadRegistry().registerIfAbsent(header->tid, [&]() {
			std::shared_ptr<Thread> tmp = nullptr;

			void* stackHint = nullptr;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				stackHint = reinterpret_cast<void*>(checkinCall->body.stack_hint);
			}

			try {
				tmp = std::make_shared<Thread>(process, header->tid, stackHint);
			} catch (std::system_error e) {
				return tmp;
			}

			tmp->setAddress(requestMessage.address());
			tmp->registerWithProcess();
			return tmp;
		});

		if (!thread) {
			callLog.error() << "Received call from non-existent thread?" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		if (thread->process() != process) {
			throw std::runtime_error("Message TID belongs to a different process");
		}

		thread->setAddress(requestMessage.address());
	}

	if (callLog.enabled(Log::Type::Debug)) {
		auto pidString = (process) ? (std::to_string(process->id()) + " (" + std::to_string(process->nsid()) + ")") : (std::to_string(header->pid) + " (-1)");
		auto tidString = (thread) ? (std::to_string(thread->id()) + " (" + std::to_string(thread->nsid()) + ")") : (std::to_string(header->tid) + " (-1)");
		callLog.debug() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from PID " << pidString << ", TID " << tidString << callLog.endLog;
	}

	if (header->number == dserver_callnum_s2c) {
		// this is an S2C reply

		{
			std::unique_lock lock(thread->_rwlock);

			if (thread->_s2cReply) {
				throw std::runtime_error("Received S2C reply but thread already had one pending");
			}

			thread->_s2cReply = std::move(requestMessage);
		}

		dtape_semaphore_up(thread->_s2cReplySempahore);

		return nullptr;
	} else if (header->number == dserver_callnum_push_reply) {
		// this is a reply push
		// (used to send interrupted replies back to the server)

		auto pushReplyCall = reinterpret_cast<const dserver_rpc_call_push_reply_t*>(requestMessage.data().data());
		Message replyToSave(pushReplyCall->reply_size, 0);

		// extract the reply-push synchronization pipe
		// owned here so it is closed on every exit; the client is blocked on the read end and EOF releases it
		FD pipeDesc(requestMessage.extractDescriptorAtIndex(requestMessage.descriptors().size() - 1));
		char tmp = 1;

		if (!pipeDesc) {
			throw std::runtime_error("Failed to extract reply-push synchronization pipe");
		}

		if (!process->readMemory(pushReplyCall->reply, replyToSave.data().data(), pushReplyCall->reply_size)) {
			throw std::runtime_error("Failed to read client-pushed reply body");
		}

		replyToSave.replaceDescriptors(requestMessage.descriptors());
		requestMessage.replaceDescriptors({});

		replyToSave.setAddress(requestMessage.address());

		{
			std::unique_lock lock(thread->_rwlock);
			if (thread->_pendingCall && thread->_pendingCall->number() == Call::Number::InterruptEnter) {
				// this means the client got interrupted after we had already sent a reply for the interrupted call,
				// the client saw this unexpected reply while waiting for interrupt_enter to respond and sent it back to us,
				// and we received both calls (interrupt_enter and push_reply) at the same time
				thread->_pendingSavedReply = std::move(replyToSave);
			} else {
				if (thread->_interrupts.empty()) {
					throw std::runtime_error("Client tried to push reply outside of interrupt");
				}
				if (thread->_interrupts.top().savedReply) {
					throw std::runtime_error("Client-pushed reply overwriting existing saved reply");
				}
				thread->_interrupts.top().savedReply = std::move(replyToSave);
			}
		}

		callLog.debug() << *thread << ": Saved client-pushed reply (" << ((thread->_pendingSavedReply) ? "pending" : "normal") << ")" << callLog.endLog;

		// write a byte to the pipe so the caller can continue
		write(pipeDesc.fd(), &tmp, sizeof(tmp));

		return nullptr;
	}

	// finally, let's construct the call class

	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_ ## _callName ## _t)) { \
				throw std::invalid_argument("Message buffer was too small for dserver_call_" #_callName "_t"); \
			} \
			result = std::make_shared<_className>(thread, reinterpret_cast<dserver_rpc_call_ ## _callName ## _t*>(header), std::move(requestMessage)); \
		} break;

	switch (header->number) {
		DSERVER_CONSTRUCT_CASES

		default:
			throw std::invalid_argument("Invalid call number");
	}

	#undef CALL_CASE

	if (thread) {
		thread->setPendingCall(result);
		return result;
	} else {
		Thread::kernelAsync([result]() {
			result->processCall();
		});
		return nullptr;
	}
};

DarlingServer::Call::Call(std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader):
	_thread(thread),
	_replyAddress(replyAddress),
	_header(*callHeader)
	{};

DarlingServer::Call::~Call() {};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Call::thread() const {
	return _thread.lock();
};

void DarlingServer::Call::sendBasicReply(int resultCode) {
	throw std::runtime_error("This call cannot send a basic reply");
};

void DarlingServer::Call::sendBSDReply(int resultCode, uint32_t returnValue) {
	throw std::runtime_error("This call cannot send a BSD reply");
};

bool DarlingServer::Call::isXNUTrap() const {
	return false;
};

bool DarlingServer::Call::isBSDTrap() const {
	return false;
};

void DarlingServer::Call::sendReply(Message&& reply) {
	Server::sharedInstance().sendMessage(std::move(reply));
};

//
// call processing
//

/*
 *
 * A note about RPC wrappers:
 *
 * The auto-generated RPC wrappers provide both client-side wrappers as well as server-side wrappers.
 * The server-side wrappers automatically handle a few things like replies and descriptors.
 *
 * Replies:
 * The RPC wrappers provide a custom `_sendReply` method specific to each call class.
 * This method takes the result/status code as its first parameter followed by the return parameters
 * specified in the call interface. When a call is done processing, it simply calls `_sendReply` with the necessary
 * parameters and the RPC wrappers will take care of setting up the message and loading it onto the reply queue
 * for the server to send it out.
 *
 * Descriptors:
 * The RPC wrappers automatically handle ownership of descriptors, both incoming and outgoing.
 *
 * Incoming descriptors are extracted from the message and ownership is moved into the call instance.
 * The call processing code can use the descriptor however it likes while the call instance is still alive.
 * If it would like to move ownership out of the call instance, it can set the descriptor in the `_body` to `-1`.
 * Descriptors still left in the `_body` when the call instance is destroyed are automatically closed.
 *
 * Ownership of outgoing descriptors is passed into the reply message. In other words, when a descriptor
 * is given to `_sendReply`, the call instance loses ownership of that descriptor. If the call instance
 * would like to retain ownership, it should `dup()` the descriptor and pass the `dup()`ed descriptor to `_sendReply` instead.
 *
 */

void DarlingServer::Call::Checkin::processCall() {
	// the Call instance creation already took care of registering the process and thread.

	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the process needs to know when the checkin occurs, in case it has a pending replacement
			// and also to notify its parent about when the fork is complete
			process->notifyCheckin(static_cast<Process::Architecture>(_header.architecture), _body.is_fork);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Checkout::processCall() {
	int code = 0;
	bool threadDied = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.exec_listener_pipe >= 0) {
				// this is actually an execve;
				// let's monitor the FD we got

				// make it non-blocking
				int flags = fcntl(_body.exec_listener_pipe, F_GETFL);
				if (flags < 0) {
					code = -errno;
				} else {
					flags |= O_NONBLOCK;
					if (fcntl(_body.exec_listener_pipe, F_SETFL, flags) < 0) {
						code = -errno;
					} else {
						// now monitor it
						auto fd = std::make_shared<FD>(_body.exec_listener_pipe);
						_body.exec_listener_pipe = -1; // the FD instance now owns the descriptor

						auto replacingWithDarlingProcess = _body.executing_macho;

						std::weak_ptr<Process> weakProcess = process;
						Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::HangUp, false, true, [fd, weakProcess, replacingWithDarlingProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
							Server::sharedInstance().removeMonitor(monitor);

							auto process = weakProcess.lock();

							if (!process) {
								// the process died...
								return;
							}

							char tmp;
							int result = read(fd->fd(), &tmp, sizeof(tmp));

							if (result < 0) {
								// we shouldn't even get EAGAIN
								throw std::system_error(errno, std::generic_category(), "Failed to read from exec listener pipe");
							}

							if (result == 0) {
								// the execve succeeded
								if (replacingWithDarlingProcess) {
									process->setPendingReplacement();
								} else {
									// the Darling process was replaced with a non-Darling process
									// treat it like death
									process->notifyDead();
								}
							} else {
								// the execve failed
								// do nothing in this case
							}
						}));
					}
				}
			} else {
				thread->notifyDead();
				threadDied = true;

				// if this was the last thread in the process, it'll be automatically unregistered
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	if (threadDied) {
		// A dead thread cannot send its reply, so reproduce the active-call cleanup
		// normally performed by Thread::pushCallReply before replying directly.
		auto self = shared_from_this();
		if (auto thread = _thread.lock()) {
			thread->deactivateCall(self);
		}
		_thread.reset();
		_sendReply(code);
		return;
	}

	_sendReply(code);
};

void DarlingServer::Call::VchrootPath::processCall() {
	int code = 0;
	size_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.buffer_size > 0) {
				auto tmpstr = process->vchrootPath().substr(0, _body.buffer_size - 1);
				auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

				fullLength = process->vchrootPath().length();

				if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::TaskSelfTrap::processCall() {
	const auto taskSelfPort = dtape_task_self_trap();
	_sendReply(0, taskSelfPort);
};

void DarlingServer::Call::HostSelfTrap::processCall() {
	const auto hostSelfPort = dtape_host_self_trap();
	_sendReply(0, hostSelfPort);
};

void DarlingServer::Call::ThreadSelfTrap::processCall() {
	const auto threadSelfPort = dtape_thread_self_trap();
	_sendReply(0, threadSelfPort);
};

void DarlingServer::Call::MachReplyPort::processCall() {
	const auto machReplyPort = dtape_mach_reply_port();
	_sendReply(0, machReplyPort);
};

void DarlingServer::Call::Kprintf::processCall() {
	static auto kprintfLog = Log("kprintf");
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			char* tmp = (char*)malloc(_body.string_length + 1);

			if (tmp) {
				if (process->readMemory(_body.string, tmp, _body.string_length, &code)) {
					size_t len = _body.string_length;

					// strip trailing whitespace
					while (len > 0 && isspace(tmp[len - 1])) {
						--len;
					}
					tmp[len] = '\0';

					kprintfLog.info() << tmp << kprintfLog.endLog;
				} else {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				}

				free(tmp);
			} else {
				code = -ENOMEM;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StartedSuspended::processCall() {
	int code = 0;
	bool suspended = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			suspended = process->startSuspended();
			process->setStartSuspended(false);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, suspended);
};

void DarlingServer::Call::GetTracer::processCall() {
	int code = 0;
	int32_t tracer = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (auto tracerProcess = process->tracerProcess()) {
				tracer = tracerProcess->nsid();
			} else {
				// leave `tracer` as 0
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, tracer);
};

void DarlingServer::Call::Uidgid::processCall() {
	int code = 0;
	int uid = -1;
	int gid = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// HACK
			// we shouldn't need to access _dtapeTask; Process should provide a method for this (but it doesn't yet because i'm not sure how to make that API feel at-home in C++)
			dtape_task_uidgid(process->_dtapeTask, _body.new_uid, _body.new_gid, &uid, &gid);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, uid, gid);
};

void DarlingServer::Call::SetThreadHandles::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->setThreadHandles(_body.pthread_handle, _body.dispatch_qaddr, _body.cancel_marked_addr);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Vchroot::processCall() {
	int code = 0;

	// TODO: wrap all `processCall` calls in try-catch like this
	try {
		if (auto thread = _thread.lock()) {
			if (auto process = thread->process()) {
				process->setVchrootDirectory(std::make_shared<FD>(_body.directory_fd));
				_body.directory_fd = -1;
			} else {
				code = -ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} catch (std::system_error err) {
		code = -err.code().value();
	} catch (...) {
		code = std::numeric_limits<int>::min();
	}

	_sendReply(code);
};

void DarlingServer::Call::MldrPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto tmpstr = std::string(Config::defaultMldrPath).substr(0, _body.buffer_size - 1);
			auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

			fullLength = process->vchrootPath().length();

			if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
				// writeMemory returns a positive error code, but we want a negative one
				code = -code;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::ThreadGetSpecialReplyPort::processCall() {
	_sendReply(0, dtape_thread_get_special_reply_port());
};

void DarlingServer::Call::MkTimerCreate::processCall() {
	_sendReply(0, dtape_mk_timer_create());
};

void DarlingServer::Call::PthreadKill::processCall() {
	int code = 0;

	if (auto targetThread = Thread::threadForPort(_body.thread_port)) {
		try {
			targetThread->sendSignal(_body.signal);
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadCanceled::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		code = thread->pthreadCanceled(_body.action);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadTestcancel::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (!thread->pthreadTestcancel()) {
			code = -EINVAL;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadMarkcancel::processCall() {
	int code = 0;

	auto thread = _thread.lock();
	auto targetThread = Thread::threadForPort(_body.thread_port);

	// like xnu, only accept threads of the caller's own task
	if (thread && targetThread && targetThread->process() && targetThread->process() == thread->process()) {
		// a thread that cancels itself is not waiting anywhere
		targetThread->pthreadMarkcancel(targetThread != thread);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::KqchanMachPortOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::MachPort>(process, _body.port_name, _body.receive_buffer, _body.receive_buffer_size, _body.saved_filter_flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the port
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::KqchanProcOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::Process>(process, _body.pid, _body.flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the process
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::FileportMakeport::processCall() {
	int code = 0;
	uint32_t portName = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.fd < 0) {
				code = -EBADF;
			} else {
				// the fileport takes ownership of the descriptor
				int fd = _body.fd;
				_body.fd = -1;

				switch (dtape_fileport_makeport(process->_dtapeTask, fd, &portName)) {
					case dtape_fileport_result_ok:
						break;
					case dtape_fileport_result_no_resources:
						code = -EAGAIN;
						break;
					case dtape_fileport_result_invalid_port:
						code = -EINVAL;
						break;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portName);
};

void DarlingServer::Call::FileportMakefd::processCall() {
	int code = 0;
	int fd = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			switch (dtape_fileport_makefd(process->_dtapeTask, _body.port_name, &fd)) {
				case dtape_fileport_result_ok:
					break;
				case dtape_fileport_result_no_resources:
					code = -EMFILE;
					break;
				case dtape_fileport_result_invalid_port:
					// not a send right to a fileport
					code = -EINVAL;
					break;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// the reply takes ownership of the new descriptor
	_sendReply(code, fd);
};

static DarlingServer::Log systemConfigLog("sysconfig");

// raised once by the first accepted push. every waiter passes the count on when it wakes up,
// so the latch stays raised for later waiters too.
static dtape_semaphore_t* systemConfigLatch(dtape_task_t* kernelTask) {
	static std::once_flag once;
	static dtape_semaphore_t* latch = nullptr;
	std::call_once(once, [kernelTask]() {
		latch = dtape_semaphore_create(kernelTask, 0);
	});
	return latch;
};

void DarlingServer::Call::SetSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			int uid = -1;
			dtape_task_uidgid(process->_dtapeTask, -1, -1, &uid, nullptr);

			// the configuration comes from the root-owned `/Library/Preferences`, so only root may push it.
			// this is checked before the caller's memory is looked at.
			if (uid != 0) {
				code = -EPERM;
			} else if (_body.config_size != sizeof(dserver_system_config_t)) {
				code = -EINVAL;
			} else if (auto latch = systemConfigLatch(Process::kernelProcess()->_dtapeTask); !latch) {
				code = -ENOMEM;
			} else {
				dserver_system_config_t config;
				bool isFirst = false;

				if (!process->readMemory(_body.config, &config, sizeof(config), &code)) {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				} else {
					code = SystemConfig::sharedInstance().apply(config, isFirst);
				}

				if (code == 0) {
					systemConfigLog.info() << "Process " << process->id() << " (" << process->nsid() << ") set the system configuration" << systemConfigLog.endLog;
					if (isFirst) {
						dtape_semaphore_up(latch);
					}
				} else {
					systemConfigLog.warning() << "Rejected the system configuration from process " << process->id() << " (" << process->nsid() << "): " << code << systemConfigLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.config_size != sizeof(dserver_system_config_t)) {
				code = -EINVAL;
			} else {
				auto config = SystemConfig::sharedInstance().current();
				if (!process->writeMemory(_body.config, &config, sizeof(config), &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::WaitSystemConfig::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (thread->process()) {
			if (SystemConfig::sharedInstance().current().generation == 0) {
				if (auto latch = systemConfigLatch(Process::kernelProcess()->_dtapeTask); !latch) {
					code = -ENOMEM;
				} else if (dtape_semaphore_down_simple(latch)) {
					// wake up the next waiter (or leave the latch raised for later ones)
					dtape_semaphore_up(latch);
				} else {
					code = -EINTR;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetPlatformIdentity::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			int uid = -1;
			dtape_task_uidgid(process->_dtapeTask, -1, -1, &uid, nullptr);

			// the identity comes from the root-owned `/Library/Preferences`, so only root may push it.
			// this is checked before the caller's memory is looked at.
			if (uid != 0) {
				code = -EPERM;
			} else if (_body.identity_size != sizeof(dserver_platform_identity_t)) {
				code = -EINVAL;
			} else {
				dserver_platform_identity_t identity;

				if (!process->readMemory(_body.identity, &identity, sizeof(identity), &code)) {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				} else {
					code = PlatformIdentity::sharedInstance().apply(identity, [](const dserver_platform_identity_t& applied) {
						// `host_info()` reports the configured memory size, as `hw.memsize` does
						dtape_host_set_memory_size(applied.memory_size);
					});
				}

				if (code == 0) {
					systemConfigLog.info() << "Process " << process->id() << " (" << process->nsid() << ") set the platform identity" << systemConfigLog.endLog;
				} else {
					systemConfigLog.warning() << "Rejected the platform identity from process " << process->id() << " (" << process->nsid() << "): " << code << systemConfigLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::GetPlatformIdentity::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.identity_size != sizeof(dserver_platform_identity_t)) {
				code = -EINVAL;
			} else {
				auto identity = PlatformIdentity::sharedInstance().current();
				if (!process->writeMemory(_body.identity, &identity, sizeof(identity), &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ForkWaitForChild::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the child inherits our task's special ports (e.g. the bootstrap port) when it
			// checks in, so the parent must not return from fork() before that. if a signal
			// interrupted the wait, have the caller wait again; the child's check-in will
			// still raise the semaphore.
			if (!process->waitForChildAfterFork()) {
				code = -EINTR;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Sigprocess::processCall() {
	int code = 0;
	int newBSDSignal = 0;

	if (auto thread = _thread.lock()) {
		try {
			thread->processSignal(_body.bsd_signal_number, _body.linux_signal_number, _body.code, _body.signal_address, _body.thread_state, _body.float_state);
			newBSDSignal = thread->pendingSignal();
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, newBSDSignal);
};

void DarlingServer::Call::TaskIs64Bit::processCall() {
	int code = 0;
	bool is64Bit = false;

	if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.id)) {
		auto targetProcess = *maybeTargetProcess;
		is64Bit = targetProcess->is64Bit();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, is64Bit);
};

void DarlingServer::Call::InterruptEnter::processCall() {
	Thread::_handleInterruptEnterForCurrentThread();

	_sendReply(0);
};

void DarlingServer::Call::InterruptExit::processCall() {
	auto thread = _thread.lock();

	dtape_thread_sigexc_exit(thread->_dtapeThread);

	_sendReply(0);

	{
		std::unique_lock lock(thread->_rwlock);

		auto tmp = std::move(thread->_interrupts.top());

		thread->_interrupts.pop();

		if (tmp.savedReply) {
			callLog.debug() << *thread << ": Going to send saved reply" << callLog.endLog;
			Server::sharedInstance().sendMessage(std::move(*tmp.savedReply));
			tmp.savedReply = std::nullopt;
		}
	}
};

void DarlingServer::Call::ConsoleOpen::processCall() {
	static Log consoleLog("console");

	int code = 0;
	int sockets[2] = { -1, -1 };

	// we don't really need bidirectional communication, so a pipe would suffice,
	// except that when you set O_NONBLOCK on one side of a pipe, it is set for both.

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		int err = errno;
		callLog.warning() << __PRETTY_FUNCTION__ << ": socketpair failed with " << err << callLog.endLog;

		// just report EMFILE for the peer
		code = EMFILE;
	} else {
		// make our side non-blocking
		int flags = fcntl(sockets[0], F_GETFL);
		if (flags < 0) {
			code = -errno;
		} else {
			flags |= O_NONBLOCK;
			if (fcntl(sockets[0], F_SETFL, flags) < 0) {
				code = -errno;
			} else {
				// now monitor it
				auto fd = std::make_shared<FD>(sockets[0]);
				std::weak_ptr<Process> weakProcess;

				if (auto thread = _thread.lock()) {
					if (auto process = thread->process()) {
						weakProcess = process;
					}
				}

				Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::Readable | Monitor::Event::HangUp, false, false, [fd, weakProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
					auto proc = weakProcess.lock();

					if (!proc || static_cast<uint64_t>(events & Monitor::Event::HangUp) != 0) {
						Server::sharedInstance().removeMonitor(monitor);
						return;
					}

					if (static_cast<uint64_t>(events & Monitor::Event::Readable) != 0) {
						std::stringstream data;
						while (true) {
							char buf[128];
							auto count = read(fd->fd(), buf, sizeof(buf) - 1);
							if (count <= 0) {
								break;
							}
							buf[count] = '\0';
							data << buf;
						}
						consoleLog.info() << *proc << ": " << data.rdbuf();
					}
				}));
			}
		}
	}

	if (code != 0) {
		if (sockets[0] >= 0) {
			close(sockets[0]);
			sockets[0] = -1;
		}
		if (sockets[1] >= 0) {
			close(sockets[1]);
			sockets[1] = -1;
		}
	}
	_sendReply(code, sockets[1]);
};

void DarlingServer::Call::SetDyldInfo::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dtape_task_set_dyld_info(process->_dtapeTask, _body.address, _body.length);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StopAfterExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setStartSuspended(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetTracer::processCall() {
	int code = 0;
	std::shared_ptr<Process> targetProcess = nullptr;
	std::shared_ptr<Process> tracerProcess = nullptr;

	if (_body.target == 0) {
		if (auto thread = _thread.lock()) {
			targetProcess = thread->process();
		}
	} else {
		if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.target)) {
			targetProcess = *maybeTargetProcess;
		}
	}

	if (targetProcess) {
		if (_body.tracer == 0) {
			// leave tracer process as nullptr
		} else {
			if (auto maybeTracerProcess = processRegistry().lookupEntryByNSID(_body.tracer)) {
				tracerProcess = *maybeTracerProcess;
			} else {
				// intentionally not negated because this is not an internal error;
				// this is a perfectly valid case
				code = ESRCH;
			}
		}

		if (code == 0 && tracerProcess) {
			code = _mediateAttach(targetProcess, tracerProcess);
		}

		if (code == 0) {
			if (!targetProcess->setTracerProcess(tracerProcess)) {
				// again, not negated because this isn't an internal error;
				// simply indicates there was already a tracer set for the target
				code = EPERM;
			}
		}
	} else {
		// ditto from before
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::TidForThread::processCall() {
	int code = 0;
	int32_t tid = 0;

	if (auto thread = Thread::threadForPort(_body.thread)) {
		tid = thread->nsid();
	} else {
		// might be user error (e.g. invalid port number or dead thread), so don't negate it
		code = ESRCH;
	}

	_sendReply(code, tid);
};

void DarlingServer::Call::PtraceSigexc::processCall() {
	int code = 0;

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.target)) {
		auto process = *maybeProcess;

		code = _mediateTracing(process);
		if (code == 0) {
			dtape_task_set_sigexc_enabled(process->_dtapeTask, _body.enabled);
			dtape_task_try_resume(process->_dtapeTask);
		}
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PtraceThupdate::processCall() {
	int code = 0;

	if (auto maybeThread = threadRegistry().lookupEntryByNSID(_body.target)) {
		auto thread = *maybeThread;
		auto process = thread->process();

		code = process ? _mediateTracing(process) : 0;
		if (code == 0) {
			thread->setPendingSignal(_body.signum);
		}
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ThreadSuspended::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->waitWhileUserSuspended(_body.thread_state, _body.float_state);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::S2CPerform::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		dtape_semaphore_up(thread->_s2cInterruptEnterSemaphore);
		dtape_semaphore_down_simple(thread->_s2cInterruptExitSemaphore);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetExecutablePath::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string tmpstr;
			tmpstr.resize(_body.buffer_size);
			if (!process->readMemory((uintptr_t)_body.buffer, tmpstr.data(), _body.buffer_size, &code)) {
				code = -code;
			} else {
				process->setExecutablePath(tmpstr.c_str());
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
}

namespace {

	// The last known path of each file that has been given a file reference. References are shared
	// between processes, so this can't live in any one of them. The server only remembers these paths:
	// it never accesses them, and the process asking for a path checks that it still leads to the file.
	class FileRefPaths {
	public:
		void remember(uint64_t device, uint64_t inode, std::string path) {
			std::unique_lock lock(_mutex);
			const Key key(device, inode);
			auto found = _entries.find(key);

			if (found != _entries.end()) {
				_order.erase(found->second);
				_entries.erase(found);
			}

			_order.emplace_front(key, std::move(path));
			_entries.emplace(key, _order.begin());

			if (_entries.size() > maximumEntries) {
				_entries.erase(_order.back().first);
				_order.pop_back();
			}
		};

		bool lookup(uint64_t device, uint64_t inode, std::string& path) {
			std::unique_lock lock(_mutex);
			auto found = _entries.find(Key(device, inode));

			if (found == _entries.end()) {
				return false;
			}

			_order.splice(_order.begin(), _order, found->second);
			path = found->second->second;
			return true;
		};

	private:
		using Key = std::pair<uint64_t, uint64_t>;
		using Entry = std::pair<Key, std::string>;

		static constexpr size_t maximumEntries = 65536;

		std::mutex _mutex;
		std::list<Entry> _order; // most recently used first
		std::map<Key, std::list<Entry>::iterator> _entries;
	};

	FileRefPaths fileRefPaths;

};

void DarlingServer::Call::FileRefRegister::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.path_length == 0) {
				code = -EINVAL;
			} else if (_body.path_length >= PATH_MAX) {
				code = -ENAMETOOLONG;
			} else {
				std::string path;
				path.resize(_body.path_length);

				if (!process->readMemory((uintptr_t)_body.path, path.data(), _body.path_length, &code)) {
					code = -code;
				} else {
					fileRefPaths.remember(_body.device, _body.inode, std::move(path));
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::FileRefPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string path;

			if (!fileRefPaths.lookup(_body.device, _body.inode, path)) {
				code = -ENOENT;
			} else {
				fullLength = path.length();

				if (path.length() >= _body.buffer_size) {
					code = -ENAMETOOLONG;
				} else if (!process->writeMemory((uintptr_t)_body.buffer, path.c_str(), path.length() + 1, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::GetExecutablePath::processCall() {
	int code = 0;
	uint64_t fullLength;

	if (auto callingThread = _thread.lock()) {
		if (auto callingProcess = callingThread->process()) {
			if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
				auto targetProcess = *maybeTargetProcess;
				auto path = targetProcess->executablePath();
				auto len = std::min(path.length() + 1, _body.buffer_size);
				if (!callingProcess->writeMemory((uintptr_t)_body.buffer, path.c_str(), len, &code)) {
					code = -code;
				}
				fullLength = path.length();
			} else {
				// not negated because this is an acceptable case.
				// e.g. the target process may have died before the call was processed.
				code = ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
}

void DarlingServer::Call::Groups::processCall() {
	int code = 0;
	std::vector<uint32_t> oldGroups;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			oldGroups = process->groups();

			if (_body.new_groups != 0 && _body.new_group_count > 0) {
				std::vector<uint32_t> newGroups;
				newGroups.resize(_body.new_group_count);

				if (!process->readMemory((uintptr_t)_body.new_groups, newGroups.data(), newGroups.size() * sizeof(uint32_t), &code)) {
					code = -code;
				} else {
					process->setGroups(newGroups);
				}
			}

			if (code == 0 && _body.old_groups != 0 && _body.old_group_space > 0) {
				auto len = std::min(oldGroups.size(), _body.old_group_space) * sizeof(uint32_t);
				if (!process->writeMemory((uintptr_t)_body.old_groups, oldGroups.data(), len, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, oldGroups.size());
};

void DarlingServer::Call::DebugListProcesses::processCall() {
	int code = 0;
	auto processes = processRegistry().copyEntries();
	int pipes[2] = {-1, -1};

	code = pipe(pipes);
	if (code == 0) {
		for (const auto& process: processes) {
			dserver_debug_process_t debugProcess;
			debugProcess.pid = process->nsid();
			debugProcess.port_count = dtape_debug_task_port_count(process->_dtapeTask);
			write(pipes[1], &debugProcess, sizeof(debugProcess));
		}

		close(pipes[1]);
	}

	_sendReply(code, processes.size(), pipes[0]);
};

void DarlingServer::Call::DebugListPorts::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_task_list_ports(process->_dtapeTask, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMembers::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_portset_list_members(process->_dtapeTask, _body.portset, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMessages::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_port_list_messages(process->_dtapeTask, _body.port, [](void* context, const dtape_debug_message_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_message_t debugMessage;

				debugMessage.sender = port->sender;
				debugMessage.size = port->size;

				write(writeFD, &debugMessage, sizeof(debugMessage));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::HostPid::processCall() {
	int code = 0;
	int32_t hostPID = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			hostPID = process->id();
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, hostPID);
};

void DarlingServer::Call::PidForHostPid::processCall() {
	int code = 0;
	int32_t pid = 0;

	if (_body.host_pid <= 0) {
		code = -ESRCH;
	} else if (auto maybeProcess = processRegistry().lookupEntryByID(_body.host_pid)) {
		pid = (*maybeProcess)->nsid();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, pid);
};

DSERVER_CLASS_SOURCE_DEFS;

//
// code signing
//

static DarlingServer::Log codeSigningLog("codesign");

// where the trust store is in the prefix when `TrustStorePath` is not set
static constexpr const char* defaultTrustStorePath = "/private/var/db/darling/trustcache";

// the key that signs the trust store, in the Darling installation (outside the prefix's writable layer)
static constexpr const char* trustStorePublicKeyPath = LIBEXEC_PATH "/private/var/db/darling/trustcache.pub";

static bool trustStoreContains(const uint8_t* cdhash) {
	auto config = DarlingServer::SystemConfig::sharedInstance().current();
	std::string path = defaultTrustStorePath;
	std::string error;

	if (config.trust_store_path[0] != '\0') {
		path.assign(config.trust_store_path, strnlen(config.trust_store_path, sizeof(config.trust_store_path)));
	}

	bool found = DarlingServer::TrustStore::sharedInstance().contains(DarlingServer::Server::sharedInstance().prefix(), path, trustStorePublicKeyPath, cdhash, error);

	if (!error.empty()) {
		codeSigningLog.warning() << "Cannot use the trust store " << path << ": " << error << codeSigningLog.endLog;
	}

	return found;
};

// looks up the process `pid` (0 for the caller); anyone may read the state of any process,
// only root may change that of another process
static int lookUpCodeSigningTarget(const std::shared_ptr<DarlingServer::Process>& caller, int32_t pid, bool modify, std::shared_ptr<DarlingServer::Process>& target) {
	if (pid == 0 || pid == caller->nsid()) {
		target = caller;
		return 0;
	}

	auto maybeTarget = DarlingServer::processRegistry().lookupEntryByNSID(pid);
	if (!maybeTarget) {
		return -ESRCH;
	}
	target = *maybeTarget;

	return (!modify || caller->guestUID() == 0) ? 0 : -EPERM;
};

int DarlingServer::Call::_mediateAttach(std::shared_ptr<Process> target, std::shared_ptr<Process> tracer) {
	using namespace CodeSigning;

	auto state = target->codeSigningState();
	if (state.code_signing_policy == dserver_code_signing_policy_off) {
		return 0;
	}

	bool isSelf = (tracer == target);
	std::shared_ptr<Process> caller;
	if (auto thread = _thread.lock()) {
		caller = thread->process();
	}

	// only the tracer itself (attaching) or the target (asking to be traced) may set a tracer
	bool fromParty = caller && (caller == tracer || caller == target);

	auto csr = SystemConfig::sharedInstance().current().csr_active_config;
	bool allowed = fromParty && attachRule(isSelf, tracer->guestUID(), target->guestUID(), state, csr);
	auto verdict = applyPolicy(state.code_signing_policy, allowed);

	if (verdict == Verdict::Denied) {
		codeSigningLog.warning() << "Attaching " << *tracer << " to " << *target << " denied" << codeSigningLog.endLog;
		// not negated, like the other errors of this call; ptrace() reports EBUSY for a process that denied attachment
		return (state.darling_flags & DSERVER_CS_DENY_ATTACH) ? EBUSY : EPERM;
	} else if (verdict == Verdict::WouldDeny) {
		codeSigningLog.info() << "Attaching " << *tracer << " to " << *target << " would be denied under enforcement" << codeSigningLog.endLog;
	}

	return 0;
};

int DarlingServer::Call::_mediateTracing(std::shared_ptr<Process> target) {
	using namespace CodeSigning;

	auto state = target->codeSigningState();
	if (state.code_signing_policy == dserver_code_signing_policy_off) {
		return 0;
	}

	std::shared_ptr<Process> caller;
	if (auto thread = _thread.lock()) {
		caller = thread->process();
	}

	// only the process's tracer, or the process itself, may change how it is traced
	bool allowed = caller && (caller == target || caller == target->tracerProcess());
	auto verdict = applyPolicy(state.code_signing_policy, allowed);

	if (verdict == Verdict::Denied) {
		codeSigningLog.warning() << "Tracing request for " << *target << " from a process that is not its tracer denied" << codeSigningLog.endLog;
		// not negated, like the other errors of these calls
		return EPERM;
	} else if (verdict == Verdict::WouldDeny) {
		codeSigningLog.info() << "Tracing request for " << *target << " from a process that is not its tracer would be denied under enforcement" << codeSigningLog.endLog;
	}

	return 0;
};

void DarlingServer::Call::CsRegisterImage::processCall() {
	int code = 0;
	uint32_t flags = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// read before anything is recorded; the descriptor stays ours (and is closed with the call).
			// pages and the CMS signature are only checked when the process's policy asks for it.
			auto policy = process->codeSigningState().code_signing_policy;
			auto image = std::make_shared<CodeSigning::Image>(CodeSigning::verifyImage(_body.image, _body.image_offset, CodeSigning::checksForPolicy(policy), trustStoreContains));

			if (!process->registerCodeSigningImage(image)) {
				code = -EPERM;
			} else {
				flags = image->state.flags;
				if (image->state.status == dserver_cs_status_invalid && !image->error.empty()) {
					codeSigningLog.info() << *process << ": the image's signature is not valid: " << image->error << codeSigningLog.endLog;
				} else if (policy == dserver_code_signing_policy_warn && !image->error.empty()) {
					codeSigningLog.warning() << *process << ": the image's signature would not be valid under enforcement: " << image->error << codeSigningLog.endLog;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, flags);
};

void DarlingServer::Call::CsGetState::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if (_body.state_size != sizeof(dserver_cs_state_t)) {
				code = -EINVAL;
			} else if ((code = lookUpCodeSigningTarget(process, _body.pid, false, target)) == 0) {
				auto state = target->codeSigningState();
				if (!process->writeMemory(_body.state, &state, sizeof(state), &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::CsCopyEntitlements::processCall() {
	int code = 0;
	uint64_t length = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if ((code = lookUpCodeSigningTarget(process, _body.pid, false, target)) == 0) {
				if (auto image = target->codeSigningImage()) {
					const auto& blob = _body.der ? image->derEntitlements : image->entitlements;
					length = blob.size();

					if (length > _body.buffer_size) {
						code = -ERANGE;
					} else if (length > 0 && !process->writeMemory(_body.buffer, blob.data(), blob.size(), &code)) {
						code = -code;
					}
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, length);
};

void DarlingServer::Call::CsUpdateFlags::processCall() {
	int code = 0;
	uint32_t flags = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::shared_ptr<Process> target;

			if ((_body.set_flags & ~CodeSigning::settableFlags()) != 0 || (_body.clear_flags & ~CodeSigning::clearableFlags()) != 0) {
				code = -EINVAL;
			} else if ((code = lookUpCodeSigningTarget(process, _body.pid, true, target)) == 0) {
				if ((_body.clear_flags & CodeSigning::libraryValidationFlags()) != 0) {
					// a process can only turn its own library validation off
					auto image = target->codeSigningImage();
					if (target != process || !CodeSigning::clearLibraryValidationRule(target->codeSigningState().code_signing_policy, image ? *image : CodeSigning::Image())) {
						code = -EPERM;
					}
				}
				if (code == 0) {
					flags = target->updateCodeSigningFlags(_body.set_flags, _body.clear_flags);
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, flags);
};

void DarlingServer::Call::CsDenyAttach::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->denyAttach();
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::CsVerifyImage::processCall() {
	int code = 0;
	uint32_t status = dserver_cs_status_invalid;
	uint32_t flags = 0;
	uint64_t codeLimit = 0;
	uint32_t pageSizeLog2 = 0;
	bool libraryValidationOk = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto state = process->codeSigningState();
			bool enforced = state.code_signing_policy == dserver_code_signing_policy_enforce;
			auto library = CodeSigning::verifyImage(_body.image, _body.image_offset, CodeSigning::checksForPolicy(state.code_signing_policy), trustStoreContains);
			auto mainImage = process->codeSigningImage();
			std::string error;

			status = library.state.status;
			flags = library.state.flags;
			codeLimit = library.state.code_limit;
			pageSizeLog2 = library.pageSizeLog2;
			// library validation only refuses anything under enforcement
			libraryValidationOk = !enforced || CodeSigning::libraryValidationAllows(state, mainImage ? *mainImage : CodeSigning::Image(), library, error);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, status, flags, codeLimit, pageSizeLog2, libraryValidationOk);
};
