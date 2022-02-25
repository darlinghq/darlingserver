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

#include <darlingserver/thread.hpp>
#include <darlingserver/process.hpp>
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/logging.hpp>
#include <filesystem>
#include <fstream>

#include <sys/mman.h>
#include <signal.h>

#include <darlingserver/duct-tape.h>
#include <atomic>

// 64KiB should be enough for us
#define THREAD_STACK_SIZE (64 * 1024ULL)
#define USE_THREAD_GUARD_PAGES 1

static thread_local std::shared_ptr<DarlingServer::Thread> currentThreadVar = nullptr;
static thread_local bool returningToThreadTop = false;
static thread_local ucontext_t backToThreadTopContext;
static thread_local libsimple_lock_t* unlockMeWhenSuspending = nullptr;
static thread_local std::function<void()> currentContinuation = nullptr;
static thread_local std::shared_ptr<DarlingServer::Call> currentCall = nullptr;

/**
 * Our microthreads use cooperative multitasking, so we don't really use interrupts per-se.
 * Rather, this is an indication to our cooperative scheduler that the microthread is doing something and
 * expects to continue to have control of the executing thread. If it calls a function/method that
 * would cause it to relinquish control of the thread, this should be considered an error.
 *
 * This is primarily of use for debugging duct-tape code and ensuring certain assumptions made in the duct-tape code hold true.
 */
static thread_local uint64_t interruptDisableCount = 0;

static DarlingServer::Log threadLog("thread");

static void* allocateStack(size_t stackSize) {
	void* stack = NULL;

#if USE_THREAD_GUARD_PAGES
	stack = mmap(NULL, stackSize + 2048ULL, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
	stack = mmap(NULL, stackSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif

	if (stack == MAP_FAILED) {
		throw std::system_error(errno, std::generic_category());
	}

#if USE_THREAD_GUARD_PAGES
	mprotect(stack, 1024ULL, PROT_NONE);
	stack = (char*)stack + 1024ULL;
	mprotect((char*)stack + stackSize, 1024ULL, PROT_NONE);
#endif

	return stack;
};

static void freeStack(void* stack, size_t stackSize) {
#if USE_THREAD_GUARD_PAGES
	if (munmap((char*)stack - 1024ULL, stackSize + 2048ULL) < 0) {
		throw std::system_error(errno, std::generic_category());
	}
#else
	if (munmap(stack, stackSize) < 0) {
		throw std::system_error(errno, std::generic_category());
	}
#endif
};

DarlingServer::Thread::Thread(std::shared_ptr<Process> process, NSID nsid):
	_nstid(nsid),
	_process(process)
{
	_tid = -1;

	for (const auto& entry: std::filesystem::directory_iterator("/proc/" + std::to_string(process->id()) + "/task")) {
		std::ifstream statusFile(entry.path() / "status");
		std::string line;

		while (std::getline(statusFile, line)) {
			if (line.substr(0, sizeof("NSpid") - 1) == "NSpid") {
				auto pos = line.find_last_of('\t');
				std::string id;

				if (pos != line.npos) {
					id = line.substr(pos + 1);
				}

				if (id.empty()) {
					throw std::runtime_error("Failed to parse thread ID");
				}

				if (std::stoi(id) != _nstid) {
					continue;
				}

				_tid = std::stoi(entry.path().filename().string());

				break;
			}
		}
	}

	if (_tid == -1) {
		throw std::runtime_error("Failed to find thread ID within darlingserver's namespace");
	}

	_stackSize = THREAD_STACK_SIZE;
	_stack = allocateStack(_stackSize);

	// NOTE: it's okay to use raw `this` without a shared pointer because the duct-taped thread will always live for less time than this Thread instance
	_dtapeThread = dtape_thread_create(process->_dtapeTask, _nstid, this);
	_s2cPerformSempahore = dtape_semaphore_create(process->_dtapeTask, 1);
	_s2cReplySempahore = dtape_semaphore_create(process->_dtapeTask, 0);

	threadLog.info() << "New thread created with ID " << _tid << " and NSID " << _nstid << " for process with ID " << (process ? process->id() : -1) << " and NSID " << (process ? process->nsid() : -1);
};

DarlingServer::Thread::Thread(KernelThreadConstructorTag tag):
	_tid(-1),
	_process(Process::kernelProcess())
{
	static uint64_t kernelThreadIDCounter = DTAPE_KERNEL_THREAD_ID_THRESHOLD;
	static std::mutex kernelThreadIDCounterLock;

	std::unique_lock idLock(kernelThreadIDCounterLock);
	_nstid = kernelThreadIDCounter++;
	if (kernelThreadIDCounter == 0) {
		kernelThreadIDCounter = DTAPE_KERNEL_THREAD_ID_THRESHOLD;
	}
	idLock.unlock();

	_stackSize = THREAD_STACK_SIZE;
	_stack = allocateStack(_stackSize);

	_dtapeThread = dtape_thread_create(Process::kernelProcess()->_dtapeTask, _nstid, this);
};

void DarlingServer::Thread::registerWithProcess() {
	auto process = _process.lock();
	std::unique_lock lock(process->_rwlock);
	process->_threads[_nstid] = shared_from_this();
};

DarlingServer::Thread::~Thread() noexcept(false) {
	freeStack(_stack, _stackSize);

	// schedule the duct-taped thread to be destroyed
	// dtape_thread_destroy needs a microthread context, so we call it within a kernel microthread
	kernelAsync([dtapeThread = _dtapeThread, s2cPerformSemaphore = _s2cPerformSempahore, s2cReplySemaphore = _s2cReplySempahore]() {
		if (s2cPerformSemaphore) {
			dtape_semaphore_destroy(s2cPerformSemaphore);
		}
		if (s2cReplySemaphore) {
			dtape_semaphore_destroy(s2cReplySemaphore);
		}
		dtape_thread_destroy(dtapeThread);
	});

	auto process = _process.lock();
	if (!process) {
		// the process is unregistering us
		return;
	}

	std::unique_lock lock(process->_rwlock);
	auto it = process->_threads.begin();
	while (it != process->_threads.end()) {
		if (it->first == _nstid) {
			break;
		}
		++it;
	}
	if (it == process->_threads.end()) {
		throw std::runtime_error("Thread was not registered with Process");
	}
	process->_threads.erase(it);

	if (process->_threads.empty()) {
		// if this was the last thread in the process, it has died, so unregister it.
		// this should already be handled by the process' pidfd monitor, but just in case, we also handle it here.
		processRegistry().unregisterEntry(process);
	}
};

DarlingServer::Thread::ID DarlingServer::Thread::id() const {
	return _tid;
};

DarlingServer::Thread::NSID DarlingServer::Thread::nsid() const {
	return _nstid;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Thread::process() const {
	return _process.lock();
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::pendingCall() const {
	std::shared_lock lock(_rwlock);
	return _pendingCall;
};

void DarlingServer::Thread::setPendingCall(std::shared_ptr<Call> newPendingCall) {
	std::unique_lock lock(_rwlock);
	if (newPendingCall && _pendingCall) {
		throw std::runtime_error("Thread's pending call overwritten while active");
	}
	_pendingCall = newPendingCall;
};

DarlingServer::Address DarlingServer::Thread::address() const {
	std::shared_lock lock(_rwlock);
	return _address;
};

void DarlingServer::Thread::setAddress(Address address) {
	std::unique_lock lock(_rwlock);
	_address = address;
};

void DarlingServer::Thread::setThreadHandles(uintptr_t pthreadHandle, uintptr_t dispatchQueueAddress) {
	dtape_thread_set_handles(_dtapeThread, pthreadHandle, dispatchQueueAddress);
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::activeSyscall() const {
	std::shared_lock lock(_rwlock);
	return _activeSyscall;
};

void DarlingServer::Thread::setActiveSyscall(std::shared_ptr<DarlingServer::Call> activeSyscall) {
	std::unique_lock lock(_rwlock);
	if (activeSyscall && _activeSyscall) {
		throw std::runtime_error("Thread's active syscall overwritten while active");
	}
	_activeSyscall = activeSyscall;
};

bool DarlingServer::Thread::waitingForReply() const {
	std::shared_lock lock(_rwlock);
	return _waitingForReply;
};

void DarlingServer::Thread::setWaitingForReply(bool waitingForReply) {
	std::unique_lock lock(_rwlock);
	_waitingForReply = waitingForReply;
};

/*
 * IMPORTANT
 * ===
 *
 * The way that microthread handling/switching is done here is... not pretty, to say the least.
 * The problem is that, in order to use XNU's Mach IPC code, we need a way to interrupt execution of a "thread" and then resume from the same point.
 * Actual threads are too heavyweight, so instead we use our own form of microthreads with cooperative multitasking.
 * Using actual threads for each managed thread would be much simpler and far less hacky, but far more resource-intensive.
 */

static const auto microthreadLog = DarlingServer::Log("microthread");

// this runs in the context of the microthread (i.e. with the microthread's stack active)
void DarlingServer::Thread::microthreadWorker() {
	currentContinuation = nullptr;
	currentCall = currentThreadVar->pendingCall();
	currentThreadVar->setPendingCall(nullptr);
	currentCall->processCall();
	currentCall = nullptr;
	setcontext(&backToThreadTopContext);
};

void DarlingServer::Thread::microthreadContinuation() {
	currentCall = nullptr;
	currentContinuation = currentThreadVar->_continuationCallback;
	currentThreadVar->_continuationCallback = nullptr;
	currentContinuation();
	currentContinuation = nullptr;
	setcontext(&backToThreadTopContext);
};

void DarlingServer::Thread::doWork() {
	// NOTE: this method MUST NOT use any local variables that require destructors.
	//       this method is actually major UB because the compiler is free to do whatever it likes with the stack,
	//       but we know what reasonable compilers (i.e. GCC and Clang) do with it and we're specifically targeting Clang, so it's okay for us.

	_rwlock.lock();

	if (_running) {
		// this is probably an error
		microthreadLog.warning() << _tid << "(" << _nstid << "): attempt to re-run already running microthread on another thread" << microthreadLog.endLog;
		_rwlock.unlock();
		return;
	}

	if (_terminating) {
		_rwlock.unlock();
		goto doneWorking;
	}

	if (_deferralState != DeferralState::NotDeferred) {
		microthreadLog.debug() << _tid << "(" << _nstid << "): execution was deferred" << microthreadLog.endLog;
		_deferralState = DeferralState::DeferredPending;
		_rwlock.unlock();
		return;
	}

	_running = true;
	currentThreadVar = shared_from_this();
	dtape_thread_entering(_dtapeThread);

	returningToThreadTop = false;
	_rwlock.unlock();

	_runningCondvar.notify_all();

	getcontext(&backToThreadTopContext);

	if (returningToThreadTop) {
		// someone jumped back to the top of the microthread
		// (that means either the microthread has been suspended or it has finished)
		//microthreadLog.debug() << _tid << "(" << _nstid << "): microthread returned to top" << microthreadLog.endLog;
		goto doneWorking;
	} else {
		returningToThreadTop = true;

		_rwlock.lock();

		if (_continuationCallback && _pendingCall) {
			// we can only have one of the two
			throw std::runtime_error("Thread has both a pending call and a pending continuation");
		}

		if (_suspended && (_pendingCallOverride || !_pendingCall)) {
			if (_pendingCallOverride) {
				microthreadLog.info() << _tid << "(" << _nstid << "): thread was suspended with a pending call override and is now resuming with a pending call" << microthreadLog.endLog;
			}
			// we were in the middle of processing a call and we need to resume now
			_suspended = false;
			_resumeContext.uc_link = &backToThreadTopContext;
			_rwlock.unlock();
			setcontext(&_resumeContext);
		} else {
			if (!_pendingCall) {
				// if we don't actually have a pending call, we have nothing to do
				_rwlock.unlock();
				goto doneWorking;
			}
			_rwlock.unlock();

			ucontext_t newContext;
			getcontext(&newContext);
			newContext.uc_stack.ss_sp = _stack;
			newContext.uc_stack.ss_size = _stackSize;
			newContext.uc_stack.ss_flags = 0;
			newContext.uc_link = &backToThreadTopContext;
			makecontext(&newContext, microthreadWorker, 0);

			setcontext(&newContext);
		}

		// inform the compiler that it shouldn't do anything that would live past the setcontext calls
		__builtin_unreachable();
	}

doneWorking:
	_rwlock.lock();
	if (_running) {
		dtape_thread_exiting(_dtapeThread);
		currentThreadVar = nullptr;
		_running = false;
	}
	if (_terminating) {
		// unregister ourselves from the thread registry
		//
		// this will not destroy our thread immediately;
		// the worker thread invoker still holds a reference on us
		threadRegistry().unregisterEntry(shared_from_this());
	}
	_rwlock.unlock();
	if (unlockMeWhenSuspending) {
		libsimple_lock_unlock(unlockMeWhenSuspending);
		unlockMeWhenSuspending = nullptr;
	}
	_runningCondvar.notify_all();
	return;
};

void DarlingServer::Thread::suspend(std::function<void()> continuationCallback, libsimple_lock_t* unlockMe) {
	if (this != currentThreadVar.get()) {
		throw std::runtime_error("Attempt to suspend thread other than current thread");
	}

	if (interruptDisableCount > 0) {
		throw std::runtime_error("Attempt to suspend thread while interrupts disabled");
	}

	_rwlock.lock();
	_suspended = true;
	_rwlock.unlock();

	unlockMeWhenSuspending = unlockMe;

	getcontext(&_resumeContext);

	_rwlock.lock();
	if (_suspended) {
		if (continuationCallback) {
			// when suspendeding with a continuation, the current continuation and call are discarded (since they can no longer be safely returned to)
			currentContinuation = nullptr;
			currentCall = nullptr;

			_continuationCallback = continuationCallback;
			_resumeContext.uc_stack.ss_sp = _stack;
			_resumeContext.uc_stack.ss_size = _stackSize;
			_resumeContext.uc_stack.ss_flags = 0;
			_resumeContext.uc_link = &backToThreadTopContext;
			makecontext(&_resumeContext, microthreadContinuation, 0);
		}
		// jump back to the top of the microthread
		_rwlock.unlock();
		setcontext(&backToThreadTopContext);
	} else {
		// we've been resumed
		_rwlock.unlock();
	}
};

void DarlingServer::Thread::resume() {
	{
		std::shared_lock lock(_rwlock);
		if (!_suspended) {
			// maybe we should throw an error here?
			return;
		}
	}

	Server::sharedInstance().scheduleThread(shared_from_this());
};

void DarlingServer::Thread::terminate() {
	if (auto process = _process.lock()) {
		if (process.get() != Process::kernelProcess().get()) {
			throw std::runtime_error("terminate() called on non-kernel thread");
		}
	} else {
		throw std::runtime_error("terminate() called on non-kernel thread");
	}

	_rwlock.lock();
	_terminating = true;

	if (currentThreadVar.get() == this) {
		// if it's the current thread, just suspend it;
		// when we return to the "top" of the microthread,
		// doWork() will see that it's terminating and clean up
		_rwlock.unlock();
		suspend();
		throw std::runtime_error("terminate() on current kernel thread returned");
	} else {
		// if it's not the current thread and it's not currently running, just remove it from the thread registry;
		// it should die once the caller releases their reference(s) on us
		if (!_running) {
			threadRegistry().unregisterEntry(shared_from_this());
		}
		// otherwise, if it IS running, once it returns to the microthread "top" and sees `_terminating = true`, it'll unregister itself
		_rwlock.unlock();
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::currentThread() {
	return currentThreadVar;
};

void DarlingServer::Thread::setupKernelThread(std::function<void()> startupCallback) {
	std::unique_lock lock(_rwlock);
	_continuationCallback = startupCallback;
	_suspended = true;
	getcontext(&_resumeContext);
	_resumeContext.uc_stack.ss_sp = _stack;
	_resumeContext.uc_stack.ss_size = _stackSize;
	_resumeContext.uc_stack.ss_flags = 0;
	_resumeContext.uc_link = &backToThreadTopContext;
	makecontext(&_resumeContext, microthreadContinuation, 0);
};

void DarlingServer::Thread::startKernelThread(std::function<void()> startupCallback) {
	setupKernelThread(startupCallback);
	resume();
};

void DarlingServer::Thread::impersonate(std::shared_ptr<Thread> thread) {
	std::shared_ptr<Thread> oldThread;

	if (thread) {
		// prevent the thread from running while we're impersonating it
		// FIXME: this may lead to blocking natively while we're on a microthread.
		//        we would prefer to block using duct-taped facilities instead.
		thread->defer(true);
	}

	{
		std::unique_lock lock(_rwlock);
		oldThread = _impersonating;
		_impersonating = thread;
	}

	if (oldThread) {
		oldThread->undefer();
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::impersonatingThread() const {
	std::shared_lock lock(_rwlock);
	return _impersonating;
};

void DarlingServer::Thread::interruptDisable() {
	if (!currentThreadVar) {
		throw std::runtime_error("interruptDisable() called with no current thread");
	}

	++interruptDisableCount;
};

void DarlingServer::Thread::interruptEnable() {
	if (!currentThreadVar) {
		throw std::runtime_error("interruptEnable() called with no current thread");
	}

	if (interruptDisableCount-- == 0) {
		throw std::runtime_error("interruptEnable() called when already enabled");
	}
};

void DarlingServer::Thread::syscallReturn(int resultCode) {
	if (!currentThreadVar) {
		throw std::runtime_error("syscallReturn() called with no current thread");
	}

	{
		auto call = currentThreadVar->activeSyscall();
		if (!call) {
			throw std::runtime_error("Attempt to return from syscall on thread with no active syscall");
		}
		if (call->isBSDTrap()) {
			call->sendBSDReply(resultCode, currentThreadVar->_bsdReturnValue);
		} else {
			call->sendBasicReply(resultCode);
		}
	}

	currentThreadVar->setActiveSyscall(nullptr);
	currentThreadVar->suspend();
	throw std::runtime_error("Thread should not continue normally after syscall return");
};

static std::queue<std::function<void()>> kernelAsyncRunnerQueue;

// we have to use a regular lock here because it needs to be lockable from both a microthread and normal thread context.
// additionally, it's only locked for brief periods.
//
// we use libsimple_lock_t so we can pass it to `suspend` to unlock it after suspending.
// XXX: we could use a std::mutex if we add an overload to `suspend` for it.
static libsimple_lock_t kernelAsyncRunnerQueueLock;

static void kernelAsyncRunnerThreadWorker() {
	while (true) {
		libsimple_lock_lock(&kernelAsyncRunnerQueueLock);

		if (kernelAsyncRunnerQueue.empty()) {
			// unlocks the lock
			DarlingServer::Thread::currentThread()->suspend(nullptr, &kernelAsyncRunnerQueueLock);
			continue;
		}

		auto func = kernelAsyncRunnerQueue.front();
		kernelAsyncRunnerQueue.pop();

		libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

		func();
	}
};

void DarlingServer::Thread::kernelAsync(std::function<void()> fn) {
	// TODO: this could scale up depending on the size of the queue (like XNU's thread calls)
	static auto runnerThread = []() {
		auto thread = std::make_shared<Thread>(KernelThreadConstructorTag());
		thread->startKernelThread(kernelAsyncRunnerThreadWorker);
		return thread;
	}();

	libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
	kernelAsyncRunnerQueue.push(fn);
	runnerThread->resume(); // resume the runner (it's most likely suspended waiting for work)
	libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);
};

void DarlingServer::Thread::kernelSync(std::function<void()> fn) {
	std::mutex mutex;
	std::condition_variable condvar;
	bool done = false;

	kernelAsync([&]() {
		fn();

		{
			std::unique_lock lock2(mutex);
			done = true;
		}

		// notify all, but there should only be one thread waiting
		condvar.notify_all();
	});

	{
		std::unique_lock lock(mutex);
		condvar.wait(lock, [&]() {
			return done;
		});
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::threadForPort(uint32_t thread_port) {
	// prevent the target thread from dying by taking the global thread registry lock
	auto registryLock = threadRegistry().scopedLock();

	dtape_thread_t* thread_handle = dtape_thread_for_port(thread_port);
	if (!thread_handle) {
		return nullptr;
	}

	Thread* thread = static_cast<Thread*>(dtape_thread_context(thread_handle));
	if (!thread) {
		return nullptr;
	}

	return thread->shared_from_this();
};

void DarlingServer::Thread::loadStateFromUser(uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_load_state_from_user(_dtapeThread, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

void DarlingServer::Thread::saveStateToUser(uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_save_state_to_user(_dtapeThread, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

int DarlingServer::Thread::pendingSignal() const {
	std::shared_lock lock(_rwlock);
	return _pendingSignal;
};

int DarlingServer::Thread::setPendingSignal(int signal) {
	std::unique_lock lock(_rwlock);
	auto pendingSignal = _pendingSignal;
	_pendingSignal = signal;
	return pendingSignal;
};

void DarlingServer::Thread::processSignal(int bsdSignalNumber, int linuxSignalNumber, int code, uintptr_t signalAddress, uintptr_t threadStateAddress, uintptr_t floatStateAddress) {
	loadStateFromUser(threadStateAddress, floatStateAddress);

	{
		std::unique_lock lock(_rwlock);
		_pendingSignal = 0;
		_processingSignal = true;
	}

	dtape_thread_process_signal(_dtapeThread, bsdSignalNumber, linuxSignalNumber, code, signalAddress);

	// LLDB commonly suspends the thread upon reception of an exception and assumes
	// that the thread will stay suspended after replying to the exception message,
	// until thread_resume() is called.
	dtape_thread_wait_while_user_suspended(_dtapeThread);

	{
		std::unique_lock lock(_rwlock);
		_processingSignal = false;
	}

	saveStateToUser(threadStateAddress, floatStateAddress);
};

void DarlingServer::Thread::handleSignal(int signal) {
	std::unique_lock lock(_rwlock);
	if (_processingSignal) {
		_pendingSignal = signal;
	} else {
		throw std::runtime_error("Attempt to handle signal while not processing signal");
	}
};

void DarlingServer::Thread::setPendingCallOverride(bool pendingCallOverride) {
	std::unique_lock lock(_rwlock);
	_pendingCallOverride = pendingCallOverride;
};

/*
 * server-to-client (S2C) calls are used by darlingserver to invoke certain functions within managed processes
 * for which there is no in-server alterative.
 *
 * for example, memory allocation can only be done by the managed process itself; there is no Linux syscall to allocate memory in another process.
 * therefore, we have to ask the process to do it for us.
 *
 * an alternative to this system is ptrace. we can attach to the managed process and execute any function we like.
 * this is made even easier by the fact that we have our own code in the managed process, meaning we can help out the server by
 * providing thunks for it to execute that already include a debug trap.
 * the problem with this alternative is that there's no good way to tell when the child is done executing the function:
 *   * we could block with waitpid, but then that would block the worker thread for an indeterminate amount of time (and we want to avoid that).
 *   * we could have the main event loop poll periodically, but polling is undesirable.
 * additionally, if someone else is already ptracing that process, we lose the ability to execute code with this approach.
 * therefore, we have this RPC-based system instead.
 *
 * there is one major drawback to this approach, however: the process we want to execute an S2C call in
 * MUST have at least one thread waiting for a message from the server. two possible solutions:
 *   1. we use a real-time signal to ask the process to execute the S2C call.
 *      note that with this approach we'd have to block the RT signal (or ignore it) while we're waiting for an RPC call
 *      so that we don't accidentally receive a normal RPC reply in the signal handler.
 *      this would probably be a bit tricky to implement correctly (without races).
 *   2. we have each process create a dedicated thread for executing S2C calls.
 * i'm currently leaning towards solution #1 because it avoids wasting extra resources unnecessarily.
 */

static DarlingServer::Log s2cLog("s2c");

DarlingServer::Message DarlingServer::Thread::_s2cPerform(Message&& call, dserver_s2c_msgnum_t expectedReplyNumber, size_t expectedReplySize) {
	std::optional<Message> reply = std::nullopt;

	// make sure we're the only one performing an S2C call on this thread
	dtape_semaphore_down(_s2cPerformSempahore);

	s2cLog.debug() << _tid << "(" << _nstid << "): Going to perform S2C call" << s2cLog.endLog;

	// at least for now, S2C calls require the target thread to be waiting for an RPC reply
	//
	// TODO: allow threads to perform S2C calls at any time
	{
		std::shared_lock lock(_rwlock);

		if (!_waitingForReply) {
			dtape_semaphore_up(_s2cPerformSempahore);
			throw std::runtime_error("Cannot perform S2C call if thread is not waiting for reply");
		}

		call.setAddress(_address);
	}

	// at least for now, in order to wait for the S2C reply, we need the calling thread to be a microthread,
	// so that waiting on the duct-taped semaphore will work
	if (!currentThread()) {
		dtape_semaphore_up(_s2cPerformSempahore);
		throw std::runtime_error("Must be in a microthread (any microthread) to wait for S2C reply");
	}

	s2cLog.debug() << _tid << "(" << _nstid << "): Going to send S2C message" << s2cLog.endLog;

	// send the call
	Server::sharedInstance().sendMessage(std::move(call));

	// now let's wait for the reply
	dtape_semaphore_down(_s2cReplySempahore);

	s2cLog.debug() << _tid << "(" << _nstid << "): Received S2C reply" << s2cLog.endLog;

	// extract the reply
	{
		std::unique_lock lock(_rwlock);

		if (!_s2cReply) {
			// impossible, but just in case
			dtape_semaphore_up(_s2cPerformSempahore);
			throw std::runtime_error("S2C reply semaphore incremented, but no reply present");
		}

		reply = std::move(_s2cReply);
		_s2cReply = std::nullopt;
	}

	s2cLog.debug() << _tid << "(" << _nstid << "): Done performing S2C call" << s2cLog.endLog;

	// we're done performing the call; allow others to have a chance at performing an S2C call on this thread
	dtape_semaphore_up(_s2cPerformSempahore);

	// partially validate the reply

	if (reply->data().size() != expectedReplySize) {
		throw std::runtime_error("Invalid S2C reply: unxpected size");
	}

	auto replyHeader = reinterpret_cast<dserver_s2c_replyhdr_t*>(reply->data().data());
	if (replyHeader->s2c_number != expectedReplyNumber) {
		throw std::runtime_error("Invalid S2C reply: unexpected S2C reply number");
	}

	return std::move(*reply);
};

uintptr_t DarlingServer::Thread::_mmap(uintptr_t address, size_t length, int protection, int flags, int fd, off_t offset, int& outErrno) {
	// XXX: not sure if we want to force all allocations in 32-bit processes to be in the 32-bit address space.
	//      for now, we leave it up to the caller.
#if 0
	auto process = _process.lock();

	if (!process) {
		throw std::runtime_error("Cannot perform mmap without valid process");
	}

	if (process->architecture() == Process::Architecture::i386 || process->architecture() == Process::Architecture::ARM32) {
		flags |= MAP_32BIT;
	}
#endif

	Message callMessage(sizeof(dserver_s2c_call_mmap_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_mmap_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_mmap;
	call->address = address;
	call->length = length;
	call->protection = protection;
	call->flags = flags;
	call->fd = fd;
	call->offset = offset;

	s2cLog.debug() << "Performing _mmap with address=" << call->address << ", length=" << call->length << ", protection=" << call->protection << ", flags=" << call->flags << ", fd=" << call->fd << ", offset=" << call->offset << s2cLog.endLog;

	auto replyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_mmap, sizeof(dserver_s2c_reply_mmap_t));
	auto reply = reinterpret_cast<dserver_s2c_reply_mmap_t*>(replyMessage.data().data());

	s2cLog.debug() << "_mmap returned address=" << reply->address << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->address;
};

int DarlingServer::Thread::_munmap(uintptr_t address, size_t length, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_munmap_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_munmap_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_munmap;
	call->address = address;
	call->length = length;

	s2cLog.debug() << "Performing _munmap with address=" << call->address << ", length=" << call->length << s2cLog.endLog;

	auto replyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_munmap, sizeof(dserver_s2c_reply_munmap_t));
	auto reply = reinterpret_cast<dserver_s2c_reply_munmap_t*>(replyMessage.data().data());

	s2cLog.debug() << "_munmap returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

uintptr_t DarlingServer::Thread::allocatePages(size_t pageCount, int protection) {
	int err = 0;
	auto result = _mmap(0, pageCount * sysconf(_SC_PAGESIZE), protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, err);
	if (result == (uintptr_t)MAP_FAILED) {
		throw std::system_error(err, std::generic_category(), "S2C mmap call failed");
	}
	return result;
};

void DarlingServer::Thread::freePages(uintptr_t address, size_t pageCount) {
	int err = 0;
	if (_munmap(address, pageCount * sysconf(_SC_PAGESIZE), err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C munmap call failed");
	}
};

void DarlingServer::Thread::waitUntilRunning() {
	std::shared_lock lock(_rwlock);
	_runningCondvar.wait(lock, [&]() {
		return _running;
	});
};

void DarlingServer::Thread::waitUntilNotRunning() {
	std::shared_lock lock(_rwlock);
	_runningCondvar.wait(lock, [&]() {
		return !_running;
	});
};

void DarlingServer::Thread::defer(bool wait) {
	std::unique_lock lock(_rwlock);

	if (_deferralState == DeferralState::NotDeferred) {
		_deferralState = DeferralState::DeferredNotPending;
	}

	if (wait) {
		_runningCondvar.wait(lock, [&]() {
			return !_running;
		});
	}
};

void DarlingServer::Thread::undefer() {
	DeferralState previousDeferralState;

	{
		std::unique_lock lock(_rwlock);
		previousDeferralState = _deferralState;
		_deferralState = DeferralState::NotDeferred;
	}

	if (previousDeferralState == DeferralState::DeferredPending) {
		Server::sharedInstance().scheduleThread(shared_from_this());
	}
};

uint32_t* DarlingServer::Thread::bsdReturnValuePointer() {
	return &_bsdReturnValue;
};
