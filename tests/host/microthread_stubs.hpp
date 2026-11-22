// Only the surrounding services are stand-ins. The scheduler, continuation,
// suspend and return functions are compiled verbatim from src/thread.cpp.
#pragma once
#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <queue>
#include <shared_mutex>
#include <stack>
#include <stdexcept>
#include <thread>
#include <ucontext.h>
#include <utility>

inline void check(bool ok, const char* message) {
	if (!ok) {
		std::fprintf(stderr, "FAIL %s\n", message);
		std::_Exit(1);
	}
}

struct libsimple_lock_t {
	pthread_t owner{};
	unsigned unlocks = 0;
	std::function<void()> afterUnlock;
};
inline void libsimple_lock_unlock(libsimple_lock_t* lock) {
	check(pthread_equal(lock->owner, pthread_self()), "suspension lock is released by its host");
	++lock->unlocks;
	if (lock->afterUnlock)
		lock->afterUnlock();
}

namespace DarlingServer {
struct Log {
	int endLog = 0;
	Log& debug() { return *this; }
	Log& warning() { return *this; }
	Log& info() { return *this; }
	template<class T> Log& operator<<(const T&) { return *this; }
};
struct StackPool {
	struct Stack {
		char* base = nullptr;
		size_t size = 0;
		bool isValid() const { return base != nullptr; }
	};
	void allocate(Stack& stack) { stack = {new char[65536], 65536}; }
	void free(Stack& stack) { delete[] stack.base; stack = {}; }
};
struct Call {
	enum class Number { Other, InterruptEnter };
	Number kind = Number::Other;
	std::function<void()> body;
	int reply = -1;
	Number number() const { return kind; }
	void processCall() { body(); }
	bool isXNUTrap() const { return true; }
	bool isBSDTrap() const { return false; }
	void sendBSDReply(int, unsigned) { std::abort(); }
	void sendBasicReply(int code) { reply = code; }
};
struct Thread: std::enable_shared_from_this<Thread> {
	enum class DeferralState { NotDeferred, DeferredNotPending, DeferredPending };
	struct InterruptContext {
		StackPool::Stack savedStack;
		std::function<void()> savedContinuation;
		std::function<void()> continuation;
		std::deque<int> savedReplies;
		std::shared_ptr<Call> interruptedCall;
	};
	int _tid = 1, _nstid = 1;
	std::shared_mutex _rwlock;
	StackPool::Stack _stack;
	ucontext_t _resumeContext{}, _topContext{}, _syscallReturnHereDuringInterrupt{};
	std::function<void()> _continuationCallback, _currentContinuation;
	std::function<void()> _interruptedContinuation;
	libsimple_lock_t* _unlockMeWhenSuspending = nullptr;
	bool _suspended = false, _running = false, _terminating = false, _dead = false;
	bool _pendingCallOverride = false, _handlingInterruptedCall = false;
	bool _didSyscallReturnDuringInterrupt = false, _interruptedForSignal = false;
	unsigned _bsdReturnValue = 0;
	std::shared_ptr<Call> _pendingCall, _activeCall;
	std::queue<std::shared_ptr<Call>> _pendingInterrupts;
	std::stack<InterruptContext> _interrupts;
	std::deque<int> _pendingSavedReplies;
	std::condition_variable_any _runningCondvar;
	DeferralState _deferralState = DeferralState::NotDeferred;
	void* _dtapeThread = this;
	pthread_t host{};
	std::function<void()> onExit;
	static StackPool stackPool;
	static std::shared_ptr<Thread> currentThread();
	static void microthreadWorker();
	static void microthreadContinuation();
	static void syscallReturn(int code);
	static void _handleInterruptEnterForCurrentThread();
	void doWork();
	void suspend(std::function<void()> continuation = nullptr, libsimple_lock_t* unlock = nullptr);
	void setupKernelThread(std::function<void()> continuation);
	void jumpToResume(void*, size_t);
	void makePendingCallActive() { _activeCall = std::move(_pendingCall); }
	void notifyDead() { std::abort(); }
	void _scheduleRelease() { std::abort(); }
};
struct Server {
	static Server& sharedInstance() { static Server server; return server; }
	void scheduleThread(std::shared_ptr<Thread>) { std::abort(); }
};
}

inline void dtape_thread_entering(void* context) {
	static_cast<DarlingServer::Thread*>(context)->host = pthread_self();
}
inline void dtape_thread_exiting(void* context) {
	auto* thread = static_cast<DarlingServer::Thread*>(context);
	check(pthread_equal(thread->host, pthread_self()),
		"doWork returns to the host that entered it");
	if (thread->onExit)
		thread->onExit();
}
inline void dtape_thread_sigexc_enter(void*) {}
inline void dtape_thread_sigexc_enter2(void*) {}
inline DarlingServer::StackPool DarlingServer::Thread::stackPool;
inline DarlingServer::Log threadLog, microthreadLog;
