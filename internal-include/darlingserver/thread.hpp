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

#ifndef _DARLINGSERVER_THREAD_HPP_
#define _DARLINGSERVER_THREAD_HPP_

#include <memory>
#include <sys/types.h>
#include <mutex>
#include <shared_mutex>

#include <darlingserver/message.hpp>
#include <darlingserver/duct-tape.h>

#include <ucontext.h>

struct DTapeHooks;

namespace DarlingServer {
	class Process;
	class Call;

	class Thread: public std::enable_shared_from_this<Thread> {
		friend class Process;

	private:
		pid_t _tid;
		pid_t _nstid;
		std::weak_ptr<Process> _process;
		std::shared_ptr<Call> _pendingCall;
		Address _address;
		mutable std::shared_mutex _rwlock;
		void* _stack;
		size_t _stackSize;
		bool _suspended = false;
		ucontext_t _resumeContext;
		dtape_thread_handle_t _dtapeThread;
		dtape_thread_continuation_callback_f _continuationCallback = nullptr;
		bool _running = false;
		bool _terminating = false;

		static void microthreadWorker();
		static void microthreadContinuation();

		friend struct ::DTapeHooks;

		struct KernelThreadConstructorTag {};

		void _startKernelThread(dtape_thread_continuation_callback_f startupCallback);

		static void interruptDisable();
		static void interruptEnable();

	public:
		using ID = pid_t;
		using NSID = ID;

		Thread(std::shared_ptr<Process> process, NSID nsid);
		Thread(KernelThreadConstructorTag tag);
		~Thread() noexcept(false);

		void registerWithProcess();

		Thread(const Thread&) = delete;
		Thread& operator=(const Thread&) = delete;
		Thread(Thread&&) = delete;
		Thread& operator=(Thread&&) = delete;

		std::shared_ptr<Process> process() const;

		std::shared_ptr<Call> pendingCall() const;
		void setPendingCall(std::shared_ptr<Call> newPendingCall);

		/**
		 * The TID of this Thread as seen from darlingserver's namespace.
		 */
		ID id() const;

		/**
		 * The TID of this Thread as seen from within the container (i.e. launchd's namespace).
		 */
		NSID nsid() const;

		Address address() const;
		void setAddress(Address address);

		void doWork();

		/**
		 * NOTE: This currently only works if this thread is the current thread.
		 *       It will throw an error in all other cases.
		 */
		void suspend(dtape_thread_continuation_callback_f continuationCallback = nullptr, libsimple_lock_t* unlockMe = nullptr);
		void resume();
		void terminate();

		static std::shared_ptr<Thread> currentThread();
	};
};

#endif // _DARLINGSERVER_THREAD_HPP_
