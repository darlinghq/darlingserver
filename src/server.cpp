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

#include <darlingserver/server.hpp>
#include <sys/socket.h>
#include <stdexcept>
#include <errno.h>
#include <cstring>
#include <unistd.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <system_error>
#include <thread>
#include <array>
#include <darlingserver/registry.hpp>
#include <sys/eventfd.h>
#include <darlingserver/duct-tape.h>
#include <sys/timerfd.h>

#include <darlingserver/logging.hpp>

static DarlingServer::Server* sharedInstancePointer = nullptr;

struct DTapeHooks {
	static void dtape_hook_thread_suspend(void* thread_context, dtape_thread_continuation_callback_f continuationCallback, libsimple_lock_t* unlockMe) {
		static_cast<DarlingServer::Thread*>(thread_context)->suspend(continuationCallback, unlockMe);
	};

	static void dtape_hook_thread_resume(void* thread_context) {
		static_cast<DarlingServer::Thread*>(thread_context)->resume();
	};

	static dtape_task_handle_t dtape_hook_current_task(void) {
		auto process = DarlingServer::Process::currentProcess();
		if (!process) {
			return NULL;
		}
		return process->_dtapeTask;
	};

	static dtape_thread_handle_t dtape_hook_current_thread(void) {
		auto thread = DarlingServer::Thread::currentThread();
		if (!thread) {
			return NULL;
		}
		return thread->_dtapeThread;
	};

	static void dtape_hook_timer_arm(uint64_t deadline_ns) {
		auto& server = DarlingServer::Server::sharedInstance();

		if (deadline_ns == UINT64_MAX) {
			deadline_ns = 0;
		}

		struct itimerspec newSpec;
		memset(&newSpec.it_interval, 0, sizeof(newSpec.it_interval));
		newSpec.it_value.tv_sec = deadline_ns / 1000000000ull;
		newSpec.it_value.tv_nsec = deadline_ns % 1000000000ull;

		std::unique_lock lock(server._timerLock);
		if (timerfd_settime(server._timerFD, TFD_TIMER_ABSTIME, &newSpec, NULL) < 0) {
			throw std::system_error(errno, std::generic_category(), "Failed to set timerfd expiration deadline");
		}

		// TODO: verify that the timer will fire if the new deadline is in the past
	};

	static void dtape_hook_log(dtape_log_level_t level, const char* message) {
		static const auto log = DarlingServer::Log("dtape");
		switch (level) {
			case dtape_log_level_debug:
				log.debug() << message << log.endLog;
				break;
			case dtape_log_level_info:
				log.info() << message << log.endLog;
				break;
			case dtape_log_level_warning:
				log.warning() << message << log.endLog;
				break;
			case dtape_log_level_error:
			default:
				log.error() << message << log.endLog;
				break;
		}
	};

	static void dtape_hook_thread_terminate(void* thread_context) {
		static_cast<DarlingServer::Thread*>(thread_context)->terminate();
	};

	static dtape_thread_handle_t dtape_hook_thread_create_kernel(void) {
		auto thread = std::make_shared<DarlingServer::Thread>(DarlingServer::Thread::KernelThreadConstructorTag());
		thread->registerWithProcess();
		DarlingServer::threadRegistry().registerEntry(thread, true);
		return thread->_dtapeThread;
	};

	static void dtape_hook_thread_start(void* thread_context, dtape_thread_continuation_callback_f startupCallback) {
		static_cast<DarlingServer::Thread*>(thread_context)->_startKernelThread(startupCallback);
	};

	static void dtape_hook_current_thread_interrupt_disable(void) {
		DarlingServer::Thread::interruptDisable();
	};

	static void dtape_hook_current_thread_interrupt_enable(void) {
		DarlingServer::Thread::interruptEnable();
	};

	static bool dtape_hook_task_read_memory(void* task_context, uintptr_t remote_address, void* local_buffer, size_t length) {
		return static_cast<DarlingServer::Process*>(task_context)->readMemory(remote_address, local_buffer, length);
	};

	static bool dtape_hook_task_write_memory(void* task_context, uintptr_t remote_address, const void* local_buffer, size_t length) {
		return static_cast<DarlingServer::Process*>(task_context)->writeMemory(remote_address, local_buffer, length);
	};

	static constexpr dtape_hooks_t dtape_hooks = {
		.thread_suspend = dtape_hook_thread_suspend,
		.thread_resume = dtape_hook_thread_resume,
		.current_task = dtape_hook_current_task,
		.current_thread = dtape_hook_current_thread,
		.timer_arm = dtape_hook_timer_arm,
		.log = dtape_hook_log,
		.thread_terminate = dtape_hook_thread_terminate,
		.thread_create_kernel = dtape_hook_thread_create_kernel,
		.thread_start = dtape_hook_thread_start,
		.current_thread_interrupt_disable = dtape_hook_current_thread_interrupt_disable,
		.current_thread_interrupt_enable = dtape_hook_current_thread_interrupt_enable,
		.task_read_memory = dtape_hook_task_read_memory,
		.task_write_memory = dtape_hook_task_write_memory,
	};
};

DarlingServer::Server::Server(std::string prefix):
	_prefix(prefix),
	_socketPath(_prefix + "/var/run/darlingserver.sock"),
	_workQueue(std::bind(&Server::_worker, this, std::placeholders::_1))
{
	sharedInstancePointer = this;

	// remove the old socket (if it exists)
	unlink(_socketPath.c_str());

	// create the socket
	_listenerSocket = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (_listenerSocket < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to create socket");
	}

	int passCred = 1;
	if (setsockopt(_listenerSocket, SOL_SOCKET, SO_PASSCRED, &passCred, sizeof(passCred)) < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to set SO_PASSCRED on socket");
	}

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	strncpy(addr.sun_path, _socketPath.c_str(), sizeof(addr.sun_path) - 1);

	if (bind(_listenerSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to bind socket");
	}

	_wakeupFD = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (_wakeupFD < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to create eventfd for on-demand epoll wakeups");
	}

	_epollFD = epoll_create1(EPOLL_CLOEXEC);
	if (_epollFD < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to create epoll context");
	}

	struct epoll_event settings;
	settings.data.ptr = this;
	settings.events = EPOLLIN | EPOLLOUT | EPOLLET;

	if (epoll_ctl(_epollFD, EPOLL_CTL_ADD, _listenerSocket, &settings) < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to add listener socket to epoll context");
	}

	settings.data.ptr = &_wakeupFD;
	settings.events = EPOLLIN | EPOLLONESHOT;

	if (epoll_ctl(_epollFD, EPOLL_CTL_ADD, _wakeupFD, &settings) < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to add eventfd to epoll context");
	}

	_outbox.setMessageArrivalNotificationCallback([this]() {
		// we don't really have to worry about the eventfd overflowing;
		// if it does, that means the main loop has been waiting a LONG time for the listener socket to become writable again.
		// in that case, we don't really care if the eventfd is being incremented; we can't send anything anyways.
		// once the socket becomes writable again, the eventfd will be monitored again.
		eventfd_write(_wakeupFD, 1);
	});

	_timerFD = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (_timerFD < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to create timer descriptor");
	}

	settings.data.ptr = &_timerFD;
	settings.events = EPOLLIN;

	if (epoll_ctl(_epollFD, EPOLL_CTL_ADD, _timerFD, &settings) < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to add timer descriptor to epoll context");
	}
};

DarlingServer::Server::~Server() {
	close(_epollFD);
	close(_wakeupFD);
	close(_listenerSocket);
	unlink(_socketPath.c_str());
};

void DarlingServer::Server::start() {
	dtape_init(&DTapeHooks::dtape_hooks);

	// force the kernel process to be created now
	Process::kernelProcess();

	while (true) {
		if (_canRead) {
			_canRead = _inbox.receiveMany(_listenerSocket);

			while (auto msg = _inbox.pop()) {
				// TODO: this could be done concurrently
				auto call = DarlingServer::Call::callFromMessage(std::move(*msg), _outbox);
				_workQueue.push(call->thread());
			}
		}

		if (_canWrite) {
			// reset the eventfd by reading from it
			eventfd_t value;
			eventfd_read(_wakeupFD, &value);
			_canWrite = _outbox.sendMany(_listenerSocket);
		}

		struct epoll_event settings;
		settings.data.ptr = &_wakeupFD;
		settings.events = (_canWrite) ? (EPOLLIN | EPOLLONESHOT) : 0;

		if (epoll_ctl(_epollFD, EPOLL_CTL_MOD, _wakeupFD, &settings) < 0) {
			throw std::system_error(errno, std::generic_category(), "Failed to modify eventfd in epoll context");
		}

		struct epoll_event events[16];
		int ret = epoll_wait(_epollFD, events, 16, -1);

		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}

			throw std::system_error(errno, std::generic_category(), "Failed to wait on epoll context");
		}

		for (size_t i = 0; i < ret; ++i) {
			struct epoll_event* event = &events[i];

			if (event->data.ptr == this) {
				if (event->events & EPOLLIN) {
					_canRead = true;
				}

				if (event->events & EPOLLOUT) {
					_canWrite = true;
				}
			} else if (event->data.ptr == &_wakeupFD) {
				// we allow the loop to go back to the top and try to send some messages
				// (if _canWrite is true, the eventfd will be reset; otherwise, there's no point in resetting it)
			} else if (event->data.ptr == &_timerFD) {
				std::unique_lock lock(_timerLock);
				uint64_t expirations = 0;

				if (read(_timerFD, &expirations, sizeof(expirations)) < 0) {
					if (errno == EAGAIN) {
						// spurious event?
						continue;
					}

					throw std::system_error(errno, std::generic_category(), "Failed to read from timerfd");
				}

				if (expirations < 1) {
					// spurious expiration?
					continue;
				}

				// we're done handling the timerfd;
				// we don't need to lock anymore (and the following call might need to arm the timer again)
				lock.unlock();

				dtape_timer_fired();
			} else if (event->events & EPOLLIN) {
				std::shared_ptr<Process>& process = *reinterpret_cast<std::shared_ptr<Process>*>(event->data.ptr);

				if (epoll_ctl(_epollFD, EPOLL_CTL_DEL, process->_pidfd, NULL) < 0) {
					throw std::system_error(errno, std::generic_category(), "Failed to remove process handle from epoll context");
				}

				process->_unregisterThreads();
				processRegistry().unregisterEntry(process);

				delete &process;
			}
		}
	}

	// shouldn't ever be reached (exiting the main loop would be an error), but just in case
	dtape_deinit();
};

void DarlingServer::Server::monitorProcess(std::shared_ptr<Process> process) {
	struct epoll_event settings;
	settings.data.ptr = new std::shared_ptr<Process>(process);
	settings.events = EPOLLIN;

	if (epoll_ctl(_epollFD, EPOLL_CTL_ADD, process->_pidfd, &settings) < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to add process descriptor to epoll context");
	}
};

DarlingServer::Server& DarlingServer::Server::sharedInstance() {
	return *sharedInstancePointer;
};

std::string DarlingServer::Server::prefix() const {
	return _prefix;
};

void DarlingServer::Server::_worker(std::shared_ptr<Thread> thread) {
	thread->doWork();
};

void DarlingServer::Server::scheduleThread(std::shared_ptr<Thread> thread) {
	_workQueue.push(thread);
};
