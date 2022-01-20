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

static DarlingServer::Log callLog("calls");

std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage(Message&& requestMessage, MessageQueue& replyQueue) {
	if (requestMessage.data().size() < sizeof(dserver_rpc_callhdr_t)) {
		throw std::invalid_argument("Message buffer was too small for call header");
	}

	dserver_rpc_callhdr_t* header = reinterpret_cast<dserver_rpc_callhdr_t*>(requestMessage.data().data());
	std::shared_ptr<Call> result = nullptr;
	std::shared_ptr<Process> process = nullptr;
	std::shared_ptr<Thread> thread = nullptr;

	// first, make sure we know this call number
	switch (header->number) {
		DSERVER_VALID_CALLNUM_CASES
			break;

		default:
			throw std::invalid_argument("Invalid call number");
	}

	// now let's lookup (and possibly create) the process and thread making this call
	process = processRegistry().registerIfAbsent(header->pid, [&]() {
		auto tmp = std::make_shared<Process>(requestMessage.pid(), header->pid);
		Server::sharedInstance().monitorProcess(tmp);
		return tmp;
	});
	thread = threadRegistry().registerIfAbsent(header->tid, [&]() {
		auto tmp = std::make_shared<Thread>(process, header->tid);
		tmp->setAddress(requestMessage.address());
		tmp->registerWithProcess();
		return tmp;
	});

	// finally, let's construct the call class

	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_ ## _callName ## _t)) { \
				throw std::invalid_argument("Message buffer was too small for dserver_call_" #_callName "_t"); \
			} \
			result = std::make_shared<_className>(replyQueue, thread, reinterpret_cast<dserver_rpc_call_ ## _callName ## _t*>(header), std::move(requestMessage)); \
		} break;

	switch (header->number) {
		DSERVER_CONSTRUCT_CASES

		default:
			throw std::invalid_argument("Invalid call number");
	}

	#undef CALL_CASE

	thread->setPendingCall(result);

	return result;
};

DarlingServer::Call::Call(MessageQueue& replyQueue, std::shared_ptr<Thread> thread, Address replyAddress):
	_replyQueue(replyQueue),
	_thread(thread),
	_replyAddress(replyAddress)
	{};

DarlingServer::Call::~Call() {};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Call::thread() const {
	return _thread.lock();
};

void DarlingServer::Call::Checkin::processCall() {
	// the Call creation already took care of registering the process and thread
	_sendReply(0);
};

void DarlingServer::Call::Checkout::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			threadRegistry().unregisterEntry(thread);

			if (thread->id() == process->id()) {
				processRegistry().unregisterEntry(process);
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
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
	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			callLog.debug() << "Got TaskSelfTrap call from " << process->nsid() << ":" << thread->nsid() << callLog.endLog;
		}
	}

	const auto taskSelfPort = dtape_task_self_trap();

	callLog.debug() << "TaskSelfTrap returning port " << taskSelfPort << callLog.endLog;

	_sendReply(0, taskSelfPort);
};

void DarlingServer::Call::HostSelfTrap::processCall() {
	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			callLog.debug() << "Got HostSelfTrap call from " << process->nsid() << ":" << thread->nsid() << callLog.endLog;
		}
	}

	const auto hostSelfPort = dtape_host_self_trap();

	callLog.debug() << "HostSelfTrap returning port " << hostSelfPort << callLog.endLog;

	_sendReply(0, hostSelfPort);
};

void DarlingServer::Call::ThreadSelfTrap::processCall() {
	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			callLog.debug() << "Got ThreadSelfTrap call from " << process->nsid() << ":" << thread->nsid() << callLog.endLog;
		}
	}

	const auto threadSelfPort = dtape_thread_self_trap();

	callLog.debug() << "ThreadSelfTrap returning port " << threadSelfPort << callLog.endLog;

	_sendReply(0, threadSelfPort);
};

void DarlingServer::Call::MachReplyPort::processCall() {
	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			callLog.debug() << "Got MachReplyPort call from " << process->nsid() << ":" << thread->nsid() << callLog.endLog;
		}
	}

	const auto machReplyPort = dtape_mach_reply_port();

	callLog.debug() << "MachReplyPort returning port " << machReplyPort << callLog.endLog;

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
	uint32_t tracer = 0;

	callLog.warning() << "GetTracer: TODO" << callLog.endLog;

	_sendReply(code, tracer);
};

void DarlingServer::Call::MachMsgOverwrite::processCall() {
	_sendReply(dtape_mach_msg_overwrite(_body.msg, _body.option, _body.send_size, _body.rcv_size, _body.rcv_name, _body.timeout, _body.notify, _body.rcv_msg, _body.rcv_limit));
};
