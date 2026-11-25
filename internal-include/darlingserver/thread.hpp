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
#include <deque>
#include <queue>
#include <atomic>
#include <vector>

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
		// atomic so that exec can reset it while holding only the process lock
		std::atomic<uintptr_t> _cancelMarkedAddress = 0;
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
		// true from the moment an S2C call is sent until its reply is consumed or abandoned; guarded by `_rwlock`
		bool _s2cCallInFlight = false;
		// true while an S2C call that was sent, but whose reply we stopped waiting for (the wait was interrupted), is still unanswered.
		// the client still performs the call and replies; that reply must be discarded when it arrives.
		// no other S2C call is sent to the thread until then, so a reply can never be matched to the wrong call
		// (the client may have been interrupted while servicing the call, and would then answer a newer call first); guarded by `_rwlock`
		bool _s2cStaleReplyPending = false;
		// whether that abandoned call was performed through the S2C interrupt (see `_s2cInterruptAbandoned`); guarded by `_rwlock`
		bool _s2cStaleReplyUsedInterrupt = false;
		// number of S2C interrupts we signalled but stopped waiting for; guarded by `_rwlock`
		size_t _s2cInterruptAbandoned = 0;
		// set by the S2C interrupt handler (S2CPerform) right before it gives the green light; guarded by `_rwlock`
		bool _s2cInterruptEntered = false;
		// the length of the mapping that the abandoned call (see `_s2cStaleReplyPending`) makes, if it is an mmap whose result
		// must be undone (0 if there is nothing to undo); guarded by `_rwlock`
		size_t _s2cStaleMappingLength = 0;
		// whether that mapping is plain read-write anonymous memory placed by the client (see `_s2cReusableStaleMappings`); guarded by `_rwlock`
		bool _s2cStaleMappingReusable = false;
		// mappings made by abandoned mmap calls, unmapped before the next S2C call on this thread; guarded by `_rwlock`
		std::vector<std::pair<uintptr_t, size_t>> _s2cStaleMappings;
		// mappings made by abandoned mmap calls for fresh read-write anonymous memory anywhere in the task. a restarted call
		// of this thread that needs such memory takes one (`_takeReusableStaleMapping()`) instead of mapping it again, so
		// that a call interrupted again and again still gets further each time; the rest are unmapped like `_s2cStaleMappings`.
		// guarded by `_rwlock`
		std::vector<std::pair<uintptr_t, size_t>> _s2cReusableStaleMappings;
		// set when an S2C wait of the current call on this thread is interrupted, so that the call can be restarted
		// (see the `current_thread_take_s2c_interrupted` duct-tape hook); only used by the thread's own microthread
		bool _s2cInterrupted = false;
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
			// replies to send once the interrupt is over, in the order they were sent originally
			std::deque<Message> savedReplies;
			std::shared_ptr<Call> interruptedCall = nullptr;
			StackPool::Stack savedStack;
			int signal = 0;
		};
		std::stack<InterruptContext> _interrupts;
		std::queue<std::shared_ptr<Call>> _pendingInterrupts;
		// replies the client pushed back for an interrupt_enter we haven't started handling yet (pending or in `_pendingInterrupts`)
		std::deque<Message> _pendingSavedReplies;
		bool _dead = false;
		std::shared_ptr<Thread> _selfReference = nullptr;

		static void microthreadWorker();
		static void microthreadContinuation();

		friend struct ::DTapeHooks;

		std::optional<Message> _s2cPerform(Message&& call, dserver_s2c_msgnum_t expectedReplyNumber, size_t expectedReplySize, int& outErrno, size_t staleMappingLength = 0, bool staleMappingReusable = false);
		void _s2cNoteStaleMapping(const Message& staleReply, size_t length, bool reusable);
		void _s2cUndoStaleMappings();
		uintptr_t _takeReusableStaleMapping(size_t length);

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

		static void _handleInterruptEnterForCurrentThread(bool transparent);

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

		void setThreadHandles(uintptr_t pthreadHandle, uintptr_t dispatchQueueAddress, uintptr_t cancelMarkedAddress);

		int pthreadCanceled(int action);
		bool pthreadTestcancel();
		void pthreadMarkcancel(bool interruptUser);

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

		/**
		 * Reads the thread's name and its user and system CPU time (in nanoseconds) from Linux.
		 *
		 * The name is the Linux thread name (at most 15 characters), written NUL-terminated into `name`.
		 *
		 * @returns `true` if the thread's information could be read; `false` if the thread is gone.
		 */
		bool getStats(char* name, size_t nameSize, uint64_t& userTimeNs, uint64_t& systemTimeNs) const;

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
