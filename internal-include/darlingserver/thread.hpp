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
#include <condition_variable>
#include <stack>
#include <queue>

#include <darlingserver/message.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/logging.hpp>
#include <darlingserver/stack-pool.hpp>
#include <darlingserver/registry.hpp>

#include <ucontext.h>

struct DTapeHooks;

namespace DarlingServer {
	class Process;
	class Call;

	class Thread: public std::enable_shared_from_this<Thread>, public Loggable {
		friend class Process;
		friend class Call; // HACK, see call.cpp
		friend class Registry<Thread>;

	public:
		enum class RunState {
			Dead = dtape_thread_state_dead,
			Running = dtape_thread_state_running,
			Stopped = dtape_thread_state_stopped,
			Interruptible = dtape_thread_state_interruptible,
			Uninterruptible = dtape_thread_state_uninterruptible,
		};

	private:
		enum class DeferralState: uint8_t {
			/**
			 * The thread has not been told to defer execution.
			 */
			NotDeferred,
			/**
			 * The thread has been told to defer execution, but no executions have actually been deferred yet.
			 */
			DeferredNotPending,
			/**
			 * The thread has been told to defer execution and there are one or more executions that have actually been deferred.
			 */
			DeferredPending,
		};

		pid_t _tid;
		pid_t _nstid;
		EternalID _eid;
		std::shared_ptr<Process> _process;
		std::shared_ptr<Call> _pendingCall;
		Address _address;
		mutable std::shared_mutex _rwlock;
		StackPool::Stack _stack;
		bool _suspended = false;
		ucontext_t _resumeContext;
		dtape_thread_t* _dtapeThread;
		std::function<void()> _continuationCallback = nullptr;
		bool _running = false;
		bool _terminating = false;
		std::shared_ptr<Call> _activeCall = nullptr;
		std::shared_ptr<Thread> _impersonating = nullptr;
		bool _processingSignal = false;
		bool _pendingCallOverride = false;
		dtape_semaphore_t* _s2cPerformSempahore = nullptr;
		dtape_semaphore_t* _s2cReplySempahore = nullptr;
		std::optional<Message> _s2cReply = std::nullopt;
		std::condition_variable_any _runningCondvar;
		DeferralState _deferralState = DeferralState::NotDeferred;
		uint32_t _bsdReturnValue = 0;
		bool _interruptedForSignal = false;
		std::function<void()> _interruptedContinuation = nullptr;
		ucontext_t _syscallReturnHereDuringInterrupt;
		bool _didSyscallReturnDuringInterrupt = false;
		bool _handlingInterruptedCall = false;
		dtape_semaphore_t* _s2cInterruptEnterSemaphore = nullptr;
		dtape_semaphore_t* _s2cInterruptExitSemaphore = nullptr;
		bool _deferReplyForS2C = false;
		std::optional<Message> _deferredReply = std::nullopt;

		struct InterruptContext {
			std::optional<Message> savedReply = std::nullopt;
			std::shared_ptr<Call> interruptedCall = nullptr;
			StackPool::Stack savedStack;
			int signal = 0;
		};
		std::stack<InterruptContext> _interrupts;
		std::queue<std::shared_ptr<Call>> _pendingInterrupts;
		std::optional<Message> _pendingSavedReply = std::nullopt;
		bool _dead = false;
		std::shared_ptr<Thread> _selfReference = nullptr;

		static void microthreadWorker();
		static void microthreadContinuation();

		friend struct ::DTapeHooks;

		std::optional<Message> _s2cPerform(Message&& call, dserver_s2c_msgnum_t expectedReplyNumber, size_t expectedReplySize);

		uintptr_t _mmap(uintptr_t address, size_t length, int protection, int flags, int fd, off_t offset, int& outErrno);
		int _munmap(uintptr_t address, size_t length, int& outErrno);
		int _mprotect(uintptr_t address, size_t length, int protection, int& outErrno);
		int _msync(uintptr_t address, size_t size, int sync_flags, int& outErrno);

		void _deferLocked(bool wait, std::unique_lock<std::shared_mutex>& lock);
		void _undeferLocked(std::unique_lock<std::shared_mutex>& lock);

		void _deactivateCallLocked(std::shared_ptr<Call> expectedCall);

		[[noreturn]]
		void jumpToResume(void* stack, size_t stackSize);

		void _dispose();
		void _scheduleRelease();

		static void _handleInterruptEnterForCurrentThread();

		static StackPool stackPool;

		void _setEternalID(EternalID eid);

	public:
		using ID = pid_t;
		using NSID = ID;

		struct KernelThreadConstructorTag {};

		Thread(std::shared_ptr<Process> process, NSID nsid, void* stackHint = nullptr);
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

		std::shared_ptr<Call> activeCall() const;
		void makePendingCallActive();
		void deactivateCall(std::shared_ptr<Call> expectedCall);

		bool waitingForReply() const;

		/**
		 * The TID of this Thread as seen from darlingserver's namespace.
		 */
		ID id() const;

		/**
		 * The TID of this Thread as seen from within the container (i.e. launchd's namespace).
		 */
		NSID nsid() const;

		EternalID eternalID() const;

		Address address() const;
		void setAddress(Address address);

		void doWork();

		/**
		 * NOTE: This currently only works if this thread is the current thread.
		 *       It will throw an error in all other cases.
		 */
		void suspend(std::function<void()> continuationCallback = nullptr, libsimple_lock_t* unlockMe = nullptr);
		void resume();
		void terminate();

		void setThreadHandles(uintptr_t pthreadHandle, uintptr_t dispatchQueueAddress);

		void startKernelThread(std::function<void()> startupCallback);
		void setupKernelThread(std::function<void()> startupCallback);

		/**
		 * Pretend to be another thread for the purpose of running duct-taped code.
		 *
		 * This is useful, for example, to trick duct-taped code into thinking
		 * that it's running on a particular user microthread when in fact
		 * it is running on a kernel microthread.
		 *
		 * Pass `nullptr` to reset.
		 */
		void impersonate(std::shared_ptr<Thread> thread);

		/**
		 * The thread that this thread is impersonating.
		 */
		std::shared_ptr<Thread> impersonatingThread() const;

		void loadStateFromUser(uint64_t threadState, uint64_t floatState);
		void saveStateToUser(uint64_t threadState, uint64_t floatState);

		int pendingSignal() const;

		/**
		 * Sets the new pending signal for this thread and returns the previous one.
		 */
		int setPendingSignal(int signal);

		void processSignal(int bsdSignalNumber, int linuxSignalNumber, int code, uintptr_t signalAddress, uintptr_t threadStateAddress, uintptr_t floatStateAddress);

		void handleSignal(int signal);

		void setPendingCallOverride(bool pendingCallOverride);

		uintptr_t allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite);
		void freePages(uintptr_t address, size_t pageCount);
		uintptr_t mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite);
		void changeProtection(uintptr_t address, size_t pageCount, int protection);
		void syncMemory(uintptr_t address, size_t size, int sync_flags);

		void defer(bool wait = false);
		void undefer();
		void waitUntilNotRunning();
		void waitUntilRunning();

		/**
		 * @note Only to be used for BSD syscalls and only for the current thread!
		 */
		uint32_t* bsdReturnValuePointer();

		void pushCallReply(std::shared_ptr<Call> expectedCall, Message&& reply);

		RunState getRunState() const;

		void waitWhileUserSuspended(uintptr_t threadStateAddress, uintptr_t floatStateAddress);
		void sendSignal(int signal) const;

		/**
		 * Informs this Thread instance that the thread it was managing has died.
		 */
		void notifyDead();
		bool isDead() const;

		/**
		 * @note Only to be used by direct XNU traps! (e.g. Mach IPC, psynch, etc.)
		 */
		[[noreturn]]
		static void syscallReturn(int resultCode);

		static std::shared_ptr<Thread> currentThread();

		/**
		 * Returns the Thread that corresponds to the given thread port in the current port space.
		 *
		 * @note This function may only be called from a microthread context.
		 */
		static std::shared_ptr<Thread> threadForPort(uint32_t thread_port);

		/**
		 * Schedules the given function to be called within a duct-taped kernel microthread.
		 */
		static void kernelAsync(std::function<void()> fn);

		/**
		 * Runs the given function on a duct-taped kernel microthread and waits for it to return.
		 */
		static void kernelSync(std::function<void()> fn);

		static void interruptDisable();
		static void interruptEnable();

		void logToStream(Log::Stream& stream) const;
	};
};

#endif // _DARLINGSERVER_THREAD_HPP_
