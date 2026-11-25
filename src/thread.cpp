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

#include "darlingserver/registry.hpp"
#include <darlingserver/thread.hpp>
#include <darlingserver/process.hpp>
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/logging.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

#include <sys/mman.h>
#include <signal.h>

#include <darlingserver/duct-tape.h>
#include <atomic>

#include <sys/syscall.h>

#if DSERVER_ASAN
	#include <sanitizer/asan_interface.h>
#endif

#include <rtsig.h>

#include <assert.h>

#include <limits>
#include <utility>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#if defined(__ANDROID__) || defined(__BIONIC__)
extern "C" {
int darling_libucontext_getcontext(ucontext_t*) __asm__("libucontext_getcontext");
int darling_libucontext_setcontext(const ucontext_t*) __asm__("libucontext_setcontext");
int darling_libucontext_swapcontext(ucontext_t*, const ucontext_t*) __asm__("libucontext_swapcontext");
void darling_libucontext_makecontext(ucontext_t*, void (*)(), int, ...) __asm__("libucontext_makecontext");
}
#define getcontext(u) darling_libucontext_getcontext(u)
#if defined(__aarch64__)
static inline void darling_dserver_makecontext_arm64(ucontext_t* ucp, void (*func)(), ...) {
	uintptr_t* sp = (uintptr_t*)((uintptr_t)ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size);
	sp = (uintptr_t*)((uintptr_t)sp & -16L);
	ucp->uc_mcontext.sp = (uintptr_t)sp;
	ucp->uc_mcontext.pc = (uintptr_t)func;
	ucp->uc_mcontext.regs[0] = 0;
	ucp->uc_mcontext.regs[19] = (uintptr_t)ucp->uc_link;
	ucp->uc_mcontext.regs[29] = 0;
	ucp->uc_mcontext.regs[30] = 0;
}
#define makecontext(u, fn, ...) darling_dserver_makecontext_arm64(u, (void(*)())fn, __VA_ARGS__)
#else
#define makecontext(u, fn, ...) darling_libucontext_makecontext(u, (void(*)())fn, __VA_ARGS__)
#endif
#define setcontext(u) darling_libucontext_setcontext(u)
#define swapcontext(ou, nu) darling_libucontext_swapcontext(ou, nu)
#endif
#include <vector>
#if defined(__aarch64__)
#include <sys/uio.h>
#include <elf.h>
#endif

// 64KiB should be enough for us
#define THREAD_STACK_SIZE (64 * 1024ULL)
#define USE_THREAD_GUARD_PAGES 1
#define IDLE_THREAD_STACK_COUNT 8

static thread_local std::shared_ptr<DarlingServer::Thread> currentThreadVar = nullptr;
static thread_local bool returningToThreadTop = false;

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

DarlingServer::StackPool DarlingServer::Thread::stackPool(IDLE_THREAD_STACK_COUNT, THREAD_STACK_SIZE, USE_THREAD_GUARD_PAGES);

// Finds which of the given threads (all in the same process) owns the stack containing `stackHint`:
// the one whose stack pointer is nearest below it. Each thread is briefly ptrace-attached to read
// its registers and is always detached again. Returns -1 if no thread matches.
//
// If no readable thread matches but exactly one thread's registers could not be read, that thread
// is returned and `guessed` is set: it is the only thread that can still be the one we want.
// With two or more unreadable threads there is no way to tell them apart, so none is chosen.
static pid_t findThreadByStackHint(const std::vector<pid_t>& ids, void* stackHint, bool& guessed) {
	pid_t chosenId = -1;
	intptr_t nearest = std::numeric_limits<intptr_t>::max();
	pid_t unreadableId = -1;
	size_t unreadableCount = 0;

	guessed = false;

	for (auto id : ids) {
		if (ptrace(PTRACE_ATTACH, id, 0, 0) == -1) {
			continue;
		}

		int status;
		int waitStatus;
		do {
			waitStatus = waitpid(id, &status, 0);
		} while (waitStatus == -1 && errno == EINTR);

		if (waitStatus < 0) {
			continue;
		}

		// the thread exited before it stopped; it is gone and no longer traced
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			continue;
		}

		uintptr_t stackPointer = 0;
		bool gotStackPointer = false;
#ifdef __x86_64__
		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, id, 0, &regs) != -1) {
			stackPointer = regs.rsp;
			gotStackPointer = true;
		}
#elif defined(__aarch64__)
		struct user_regs_struct regs;
		struct iovec iov = { &regs, sizeof(regs) };
		if (ptrace(PTRACE_GETREGSET, id, (void*)NT_PRSTATUS, &iov) != -1) {
			stackPointer = regs.sp;
			gotStackPointer = true;
		}
#else
	#error Unsupported architecture
#endif

		if (gotStackPointer) {
			intptr_t stackDiff = (intptr_t)stackHint - (intptr_t)stackPointer;
			if (stackDiff >= 0 && stackDiff < nearest) {
				chosenId = id;
				nearest = stackDiff;
			}
		}
		else {
			// e.g. a thread that has not reached its ptrace stop yet; it is still detached below
			unreadableId = id;
			++unreadableCount;
		}

		// this is critical: we're tracing a process but cannot detach from it, and it'll not run normally.
		if (ptrace(PTRACE_DETACH, id, 0, 0) == -1) {
			throw std::system_error(errno, std::generic_category(), "Failed to detach from process.");
		}
	}

	if (chosenId == -1 && unreadableCount == 1) {
		chosenId = unreadableId;
		guessed = true;
	}

	return chosenId;
};

DarlingServer::Thread::Thread(std::shared_ptr<Process> process, NSID nsid, void* stackHint):
	_nstid(nsid),
	_process(process)
{
	_tid = -1;

	auto& scanRegistry = threadRegistry();
	for (const auto& entry: std::filesystem::directory_iterator("/proc/" + std::to_string(process->id()) + "/task")) {
		// a thread that is already registered is not the one being created; skipping it keeps the cost of
		// creating a thread independent of how many threads the process already has (reading every
		// thread's status file made each creation cost time proportional to the thread count, with the
		// server's single loop blocked meanwhile)
		pid_t candidate = 0;
		try {
			candidate = std::stoi(entry.path().filename().string());
		} catch (const std::exception&) {
			continue;
		}
		if (scanRegistry.lookupEntryByID(candidate).has_value()) {
			continue;
		}

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

				_tid = candidate;

				break;
			}
		}

		if (_tid != -1) {
			break;
		}
	}

	// if we can't determine the thread id from procfs, try some other more costly methods.
	if (_tid == -1) {
		std::vector<pid_t> ids;
		auto& registry = threadRegistry();
		for (const auto& entry: std::filesystem::directory_iterator("/proc/" + std::to_string(process->id()) + "/task")) {
			pid_t currentId = std::stoi(entry.path().filename().string());
			// Skip threads that are already registered, as we're sure they're not the ones we want.
			if (registry.lookupEntryByID(currentId).has_value()) {
				continue;
			}
			ids.push_back(currentId);
		}

		// we're sure this is the thread we want as this is the only unregistered thread.
		if (ids.size() == 1) {
			_tid = ids[0];
		} else if (stackHint != nullptr) {
			bool guessed;
			_tid = findThreadByStackHint(ids, stackHint, guessed);
			if (guessed) {
				threadLog.debug() << "Stack hint matched no readable thread; using thread " << _tid << ", the only one whose registers could not be read" << threadLog.endLog;
			}
		}
	}

	if (_tid == -1) {
		throw std::system_error(ESRCH, std::generic_category(), "Failed to find thread ID within darlingserver's namespace");
	}

	// NOTE: it's okay to use raw `this` without a shared pointer because the duct-taped thread will always live for less time than this Thread instance
	_dtapeThread = dtape_thread_create(process->_dtapeTask, _nstid, this);
	_s2cPerformSempahore = dtape_semaphore_create(process->_dtapeTask, 1);
	_s2cReplySempahore = dtape_semaphore_create(process->_dtapeTask, 0);
	_s2cInterruptEnterSemaphore = dtape_semaphore_create(process->_dtapeTask, 0);
	_s2cInterruptExitSemaphore = dtape_semaphore_create(process->_dtapeTask, 0);

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

	_dtapeThread = dtape_thread_create(Process::kernelProcess()->_dtapeTask, _nstid, this);
};

void DarlingServer::Thread::registerWithProcess() {
	std::unique_lock lock(_process->_rwlock);
	_process->_threads[_nstid] = shared_from_this();
};

DarlingServer::Thread::~Thread() noexcept(false) {
	threadLog.info() << *this << ": thread being destroyed" << threadLog.endLog;

	if (_stack.isValid()) {
		stackPool.free(_stack);
	}

	if (!_process) {
		return;
	}

	std::unique_lock lock(_process->_rwlock);
	auto it = _process->_threads.begin();
	while (it != _process->_threads.end()) {
		if (it->first == _nstid) {
			break;
		}
		++it;
	}
	if (it == _process->_threads.end()) {
		throw std::runtime_error("Thread was not registered with Process");
	}
	_process->_threads.erase(it);

	if (_process->_threads.empty()) {
		// if this was the last thread in the process, it has died, so unregister it.
		// this should already be handled by the process' pidfd monitor, but just in case, we also handle it here.
		lock.unlock();
		_process->notifyDead();
	}
};

DarlingServer::Thread::ID DarlingServer::Thread::id() const {
	return _tid;
};

DarlingServer::Thread::NSID DarlingServer::Thread::nsid() const {
	return _nstid;
};

DarlingServer::EternalID DarlingServer::Thread::eternalID() const {
	return _eid;
};

void DarlingServer::Thread::_setEternalID(EternalID eid) {
	_eid = eid;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Thread::process() const {
	return _process;
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::pendingCall() const {
	std::shared_lock lock(_rwlock);
	return _pendingCall;
};

void DarlingServer::Thread::setPendingCall(std::shared_ptr<Call> newPendingCall) {
	std::unique_lock lock(_rwlock);
	if (newPendingCall && _pendingCall) {
		if (newPendingCall->number() == Call::Number::InterruptEnter) {
			// InterruptEnter calls can occur after we receive a call but before we start processing it,
			// so we need to handle this case gracefully. we do so by saving the interrupt and scheduling
			// it to be processed once the pending call becomes active and suspends or exits.
			_pendingInterrupts.push(newPendingCall);
			return;
		} else {
			throw std::runtime_error("Thread's pending call overwritten while active");
		}
	}
	_pendingCall = newPendingCall;
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::activeCall() const {
	std::shared_lock lock(_rwlock);
	return _activeCall;
};

void DarlingServer::Thread::makePendingCallActive() {
	std::unique_lock lock(_rwlock);
	_activeCall = _pendingCall;
	_pendingCall = nullptr;
};

void DarlingServer::Thread::_deactivateCallLocked(std::shared_ptr<Call> expectedCall) {
	if ((_interruptedForSignal ? _interrupts.top().interruptedCall : _activeCall).get() != expectedCall.get()) {
		throw std::runtime_error("Upon deactivating the active call found active/interrupted call != expected call");
	}
	(_interruptedForSignal ? _interrupts.top().interruptedCall : _activeCall) = nullptr;
};

void DarlingServer::Thread::deactivateCall(std::shared_ptr<Call> expectedCall) {
	std::unique_lock lock(_rwlock);
	_deactivateCallLocked(expectedCall);
};

DarlingServer::Address DarlingServer::Thread::address() const {
	std::shared_lock lock(_rwlock);
	return _address;
};

void DarlingServer::Thread::setAddress(Address address) {
	std::unique_lock lock(_rwlock);
	_address = address;
};

void DarlingServer::Thread::setThreadHandles(uintptr_t pthreadHandle, uintptr_t dispatchQueueAddress, uintptr_t cancelMarkedAddress) {
	dtape_thread_set_handles(_dtapeThread, pthreadHandle, dispatchQueueAddress);

	std::unique_lock lock(_rwlock);
	_cancelMarkedAddress = cancelMarkedAddress;
};

int DarlingServer::Thread::pthreadCanceled(int action) {
	return -dtape_thread_pthread_canceled(_dtapeThread, action);
};

bool DarlingServer::Thread::pthreadTestcancel() {
	return dtape_thread_pthread_testcancel(_dtapeThread);
};

void DarlingServer::Thread::pthreadMarkcancel(bool interruptUser) {
	dtape_thread_t* dtapeThread = nullptr;
	bool interrupt = false;

	{
		std::shared_lock lock(_rwlock);
		if (_dead || !_dtapeThread) {
			return;
		}
		// the duct-taped thread is released asynchronously once we're dead,
		// so keep it alive while we use it outside the lock
		dtapeThread = _dtapeThread;
		dtape_thread_retain(dtapeThread);
	}

	bool marked = dtape_thread_pthread_markcancel(dtapeThread, &interrupt);
	dtape_thread_release(dtapeThread);

	if (!marked) {
		return;
	}

	bool waiting = false;

	{
		// a thread checks out (which marks it dead) before it unmaps its stack, and with it its TSD.
		// holding the lock across the accesses keeps it from dying in between, so we never touch freed memory.
		std::shared_lock lock(_rwlock);
		if (_dead) {
			return;
		}
		uintptr_t address = _cancelMarkedAddress;
		auto proc = process();

		// the TSD slot is pointer-sized (4 bytes for i386 processes, 8 bytes otherwise), and the thread zeroes it
		// when it registers it. its first byte is ours: setting it to 1 lets the thread know that it has to ask us
		// at cancellation points (the slot then reads as nonzero in either width). its second byte belongs to
		// the thread, which sets it while it waits at a cancellation point in user space (e.g. in a ulock wait).
		if (address != 0) {
			uint8_t flag = 1;
			if (!proc || !proc->writeMemory(address, &flag, sizeof(flag))) {
				threadLog.warning() << *this << ": failed to set the cancel flag" << threadLog.endLog;
			} else if (interrupt && interruptUser) {
				// the thread sets its byte before it checks ours, and we check its byte after we set ours,
				// so either it sees our flag before it waits, or we see that it waits (or both)
				std::atomic_thread_fence(std::memory_order_seq_cst);

				uint8_t threadWaiting = 0;
				if (proc->readMemory(address + 1, &threadWaiting, sizeof(threadWaiting))) {
					waiting = threadWaiting != 0;
				}
			}
		}
	}

	// in xnu, a ulock wait is an abort-safe kernel wait that thread_abort_safely() ends with EINTR.
	// here, it is a futex wait in the thread itself, out of reach of the duct-taped thread_abort_safely().
	// interrupt it with the signal that thread_hold() uses: with no suspension pending, its handler only tells us
	// about the interruption, and libsystem_kernel makes the cancelable wait return EINTR.
	if (waiting) {
		try {
			sendSignal(LINUX_SIGRTMIN);
		} catch (const std::system_error& e) {
			// the thread has exited in the meantime
			threadLog.debug() << *this << ": failed to interrupt the thread for cancellation: " << e.code() << threadLog.endLog;
		}
	}
};

bool DarlingServer::Thread::waitingForReply() const {
	std::shared_lock lock(_rwlock);
	return !!_activeCall;
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
	// The microthread can move to another host while processing a call. Its
	// identity and return context belong to Thread, not to the host's TLS.
	Thread* self = currentThread().get();
#if DSERVER_ASAN
	__sanitizer_finish_switch_fiber(self->_asanOldFakeStack, &self->_asanOldStackBottom, &self->_asanOldStackSize);
	self->_asanOldFakeStack = nullptr;
#endif

	self->_currentContinuation = nullptr;
	self->makePendingCallActive();
	self->_activeCall->processCall();

	if (self->_handlingInterruptedCall) {
		self->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		__sanitizer_start_switch_fiber(NULL, self->_stack.base, self->_stack.size);
#endif
		setcontext(&self->_syscallReturnHereDuringInterrupt);
	} else {
#if DSERVER_ASAN
		// we're exiting normally, so we might not re-enter this microthread; tell ASAN to drop the fake stack
		__sanitizer_start_switch_fiber(NULL, self->_asanOldStackBottom, self->_asanOldStackSize);
#endif

		setcontext(&self->_topContext);
	}
	__builtin_unreachable();
};

void DarlingServer::Thread::microthreadContinuation() {
	Thread* self = currentThread().get();
#if DSERVER_ASAN
	__sanitizer_finish_switch_fiber(self->_asanOldFakeStack, &self->_asanOldStackBottom, &self->_asanOldStackSize);
	self->_asanOldFakeStack = nullptr;
#endif

	self->_currentContinuation = std::exchange(self->_continuationCallback, nullptr);
	// FIXME: we probably should never see `_currentContinuation == nullptr`
	if (self->_currentContinuation) {
		self->_currentContinuation();
		self->_currentContinuation = nullptr;
	}

	if (self->_handlingInterruptedCall) {
		self->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		__sanitizer_start_switch_fiber(NULL, self->_stack.base, self->_stack.size);
#endif
		setcontext(&self->_syscallReturnHereDuringInterrupt);
	} else {
#if DSERVER_ASAN
		// see microthreadWorker()
		__sanitizer_start_switch_fiber(NULL, self->_asanOldStackBottom, self->_asanOldStackSize);
#endif
		setcontext(&self->_topContext);
	}
	__builtin_unreachable();
};

void DarlingServer::Thread::doWork() {
	// NOTE: this method MUST NOT use any local variables that require destructors.
	//       this method is actually major UB because the compiler is free to do whatever it likes with the stack,
	//       but we know what reasonable compilers (i.e. GCC and Clang) do with it and we're specifically targeting Clang, so it's okay for us.

	_rwlock.lock();

	if (_deferralState != DeferralState::NotDeferred) {
		microthreadLog.debug() << _tid << "(" << _nstid << "): execution was deferred" << microthreadLog.endLog;
		_deferralState = DeferralState::DeferredPending;
		_rwlock.unlock();
		return;
	}

	if (_running) {
		// this is probably an error
		microthreadLog.warning() << _tid << "(" << _nstid << "): attempt to re-run already running microthread on another thread" << microthreadLog.endLog;
		_rwlock.unlock();
		return;
	}

	if (_terminating) {
		goto doneWorking;
	}

	if (_dead && !_activeCall) {
		// should be impossible, since this should be handled in `notifyDead`, but just in case
		_terminating = true;
		goto doneWorking;
	}

	_running = true;
	currentThreadVar = shared_from_this();
	dtape_thread_entering(_dtapeThread);

	returningToThreadTop = false;
	_rwlock.unlock();

	_runningCondvar.notify_all();

	getcontext(&_topContext);

	if (returningToThreadTop) {
		// someone jumped back to the top of the microthread
		// (that means either the microthread has been suspended or it has finished)

#if DSERVER_ASAN
		__sanitizer_finish_switch_fiber(_asanOldFakeStack, &_asanOldStackBottom, &_asanOldStackSize);
		_asanOldFakeStack = nullptr;
#endif

		_rwlock.lock();

		if (!_suspended || _continuationCallback) {
			// we discard the old stack when either:
			//   * we exit normally (i.e. without suspending); this includes syscall returns.
			//   * or when we suspend with a continuation callback.
			stackPool.free(_stack);
		}

		//microthreadLog.debug() << _tid << "(" << _nstid << "): microthread returned to top" << microthreadLog.endLog;
		goto doneWorking;
	} else {
		returningToThreadTop = true;

		_rwlock.lock();

		if (!_pendingCallOverride && _pendingCall && _pendingCall->number() == Call::Number::InterruptEnter) {
			_interrupts.emplace();
			_interrupts.top().savedStack = _stack;
			_interrupts.top().savedContinuation = std::exchange(_currentContinuation, nullptr);
			_stack = StackPool::Stack();
			_interruptedContinuation = _continuationCallback;
			_continuationCallback = nullptr;
			_interrupts.top().interruptedCall = _activeCall;
			_activeCall = nullptr;
		}

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
			_resumeContext.uc_link = &_topContext;
			_rwlock.unlock();

			if (_continuationCallback) {
				// for continuations, we discard the old stack and start with a new one
				assert(!_stack.isValid());
				stackPool.allocate(_stack);

				// we also ahve to set up the resume context properly with the new stack
				_resumeContext.uc_stack.ss_sp = _stack.base;
				_resumeContext.uc_stack.ss_size = _stack.size;
				_resumeContext.uc_stack.ss_flags = 0;
				_resumeContext.uc_link = &_topContext;
				makecontext(&_resumeContext, microthreadContinuation, 0);
			} else {
				// otherwise, we expect to have a valid stack to continue where we left off
				assert(_stack.isValid());
			}

#if DSERVER_ASAN
			__sanitizer_start_switch_fiber(&_asanOldFakeStack, _stack.base, _stack.size);
#endif

			setcontext(&_resumeContext);
		} else {
			if (!_pendingCall) {
				// if we don't actually have a pending call, we have nothing to do
				goto doneWorking;
			}
			_suspended = false;
			_rwlock.unlock();

			// we might've had a valid stack if we're overwriting a previous suspension, so handle that.
			if (_stack.isValid()) {
				stackPool.free(_stack);
			}

			stackPool.allocate(_stack);

			ucontext_t newContext;
			getcontext(&newContext);
			newContext.uc_stack.ss_sp = _stack.base;
			newContext.uc_stack.ss_size = _stack.size;
			newContext.uc_stack.ss_flags = 0;
			newContext.uc_link = &_topContext;
			makecontext(&newContext, microthreadWorker, 0);

#if DSERVER_ASAN
			__sanitizer_start_switch_fiber(&_asanOldFakeStack, _stack.base, _stack.size);
#endif

			setcontext(&newContext);
		}

		// inform the compiler that it shouldn't do anything that would live past the setcontext calls
		__builtin_unreachable();
	}

doneWorking:
	// we must be holding `_rwlock` when we get here
	// Detach the unlock before publishing that another host may run us.
	// Releasing it can wake a host that immediately suspends with a new lock.
	libsimple_lock_t* unlockMe = std::exchange(_unlockMeWhenSuspending, nullptr);
	if (_running) {
		dtape_thread_exiting(_dtapeThread);
		currentThreadVar = nullptr;
		_running = false;
	}
	bool canRelease = false;
	if (_dead) {
		threadLog.debug() << *this << ": dead thread returning. active call? " << (!!_activeCall ? "true" : "false") << " terminating? " << (_terminating ? "true" : "false") << threadLog.endLog;
	}
	if (_dead && !_activeCall && !_terminating) {
		// this is the case when `notifyDead` notified us we were dead
		// but we had an active call and had to finish it first
		_terminating = true;
		canRelease = true;
	}
	if (_terminating && !_dead) {
		// this will not destroy our thread immediately;
		// the worker thread invoker still holds a reference on us
		_rwlock.unlock();
		notifyDead();
	} else {
		// if we have any pending interrupts, schedule them to be processed now
		// (we've just finished or suspended a call, so now's the time to handle interrupts)
		if (!_terminating && !_dead && !_pendingInterrupts.empty()) {
			if (_pendingCall) {
				throw std::runtime_error("Need to schedule interrupt for processing, but thread has pending call");
			}

			_pendingCall = _pendingInterrupts.front();
			_pendingInterrupts.pop();

			Server::sharedInstance().scheduleThread(shared_from_this());
		}

		_rwlock.unlock();
	}
	if (unlockMe) {
		libsimple_lock_unlock(unlockMe);
	}
	_runningCondvar.notify_all();
	if (canRelease) {
		_scheduleRelease();
	}
	return;
};

[[gnu::noinline]] void DarlingServer::Thread::suspend(std::function<void()> continuationCallback, libsimple_lock_t* unlockMe) {
	if (this != currentThread().get()) {
		throw std::runtime_error("Attempt to suspend thread other than current thread");
	}

	if (interruptDisableCount > 0) {
		throw std::runtime_error("Attempt to suspend thread while interrupts disabled");
	}

	_rwlock.lock();
	_suspended = true;
	_rwlock.unlock();

	_unlockMeWhenSuspending = unlockMe;

	getcontext(&_resumeContext);

	_rwlock.lock();
	if (_suspended) {
		if (continuationCallback) {
			// when suspendeding with a continuation, the current continuation and call are discarded (since they can no longer be safely returned to)
			_currentContinuation = nullptr;

			_continuationCallback = std::move(continuationCallback);
		}
		// jump back to the top of the microthread
		_rwlock.unlock();

#if DSERVER_ASAN
		// if we have a continuation, we don't expect to come back here
		__sanitizer_start_switch_fiber((_continuationCallback) ? nullptr : &_asanOldFakeStack, _asanOldStackBottom, _asanOldStackSize);
#endif

		setcontext(&_topContext);
		__builtin_unreachable();
	} else {
		// we've been resumed

		// make sure we don't have a continuation when we get here;
		// if we do, that means that doWork() failed to do its job for the continuation case
		assert(!_continuationCallback);

		_rwlock.unlock();

#if DSERVER_ASAN
		__sanitizer_finish_switch_fiber(_asanOldFakeStack, &_asanOldStackBottom, &_asanOldStackSize);
		_asanOldFakeStack = nullptr;
#endif
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
	if (_process) {
		if (_process.get() != Process::kernelProcess().get()) {
			throw std::runtime_error("terminate() called on non-kernel thread");
		}
	} else {
		throw std::runtime_error("terminate() called on non-kernel thread");
	}

	_rwlock.lock();
	_terminating = true;

	if (currentThread().get() == this) {
		// if it's the current thread, just suspend it;
		// when we return to the "top" of the microthread,
		// doWork() will see that it's terminating and clean up
		_rwlock.unlock();
		suspend();
		throw std::runtime_error("terminate() on current kernel thread returned");
	} else {
		// if it's not the current thread and it's not currently running, just tell it died;
		// it should die once the caller releases their reference(s) on us
		if (!_running) {
			_rwlock.unlock();
			notifyDead();
		} else {
			// otherwise, if it IS running, once it returns to the microthread "top" and sees `_terminating = true`, it'll unregister itself
			_rwlock.unlock();
		}
	}
};

// Returning a value prevents the compiler from treating this as a pure TLS
// address computation and reusing that address after a microthread migrates.
[[gnu::noinline]] std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::currentThread() {
	return currentThreadVar;
};

void DarlingServer::Thread::setupKernelThread(std::function<void()> startupCallback) {
	std::unique_lock lock(_rwlock);
	_continuationCallback = startupCallback;
	_suspended = true;
	getcontext(&_resumeContext);
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
		{
			std::unique_lock lock(thread->_rwlock);
			thread->_deferLocked(true, lock);
			thread->_running = true;
		}
		thread->_runningCondvar.notify_all();
	}

	{
		std::unique_lock lock(_rwlock);
		oldThread = _impersonating;
		_impersonating = thread;
	}

	if (oldThread) {
		{
			std::unique_lock lock(oldThread->_rwlock);
			oldThread->_running = false;
			oldThread->_undeferLocked(lock);
		}
		oldThread->_runningCondvar.notify_all();
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::impersonatingThread() const {
	std::shared_lock lock(_rwlock);
	return _impersonating;
};

void DarlingServer::Thread::interruptDisable() {
	++interruptDisableCount;
};

void DarlingServer::Thread::interruptEnable() {
	if (interruptDisableCount-- == 0) {
		throw std::runtime_error("interruptEnable() called when already enabled");
	}
};

void DarlingServer::Thread::syscallReturn(int resultCode) {
	Thread* self = currentThread().get();
	if (!self) {
		throw std::runtime_error("syscallReturn() called with no current thread");
	}

	{
		auto call = (self->_interruptedForSignal) ? self->_interrupts.top().interruptedCall : self->_activeCall;
		if (!call || !call->isXNUTrap()) {
			throw std::runtime_error("Attempt to return from syscall on thread with no active syscall");
		}
		if (call->isBSDTrap()) {
			call->sendBSDReply(resultCode, self->_bsdReturnValue);
		} else {
			call->sendBasicReply(resultCode);
		}
	}

	if (self->_interruptedForSignal) {
		self->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		if (self->_handlingInterruptedCall) {
			__sanitizer_start_switch_fiber(nullptr, self->_stack.base, self->_stack.size);
		}
#endif
		setcontext(&self->_syscallReturnHereDuringInterrupt);
		__builtin_unreachable();
	}

	// jump back to the top of the thread
#if DSERVER_ASAN
	__sanitizer_start_switch_fiber(nullptr, self->_asanOldStackBottom, self->_asanOldStackSize);
#endif
	setcontext(&self->_topContext);
	__builtin_unreachable();
};

static std::queue<std::function<void()>> kernelAsyncRunnerQueue;

// we have to use a regular lock here because it needs to be lockable from both a microthread and normal thread context.
// additionally, it's only locked for brief periods.
//
// we use libsimple_lock_t so we can pass it to `suspend` to unlock it after suspending.
// XXX: we could use a std::mutex if we add an overload to `suspend` for it.
static libsimple_lock_t kernelAsyncRunnerQueueLock;
static dtape_semaphore_t* kernelAsyncRunnerQueueSempahore = nullptr;
static uint64_t kernelAsyncRunnersAvailable = 0;
static std::vector<std::shared_ptr<DarlingServer::Thread>> permanentKernelAsyncRunners;

#define MAX_PERMANENT_KERNEL_RUNNERS 10

static void kernelAsyncRunnerThreadWorker(bool permanent, std::shared_ptr<DarlingServer::Thread> self) {
	do {
		// we're going to wait for work; we're available now.
		libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
		++kernelAsyncRunnersAvailable;
		libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

		if (!dtape_semaphore_down_simple(kernelAsyncRunnerQueueSempahore)) {
			// we were interrupted. go again if we're permanent; otherwise, die.
			libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
			--kernelAsyncRunnersAvailable;
			libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

			if (permanent) {
				continue;
			} else {
				break;
			}
		}

		libsimple_lock_lock(&kernelAsyncRunnerQueueLock);

		if (kernelAsyncRunnerQueue.empty()) {
			// we didn't find any work (we were probably awoken spuriously).
			// go again if we're permanent; otherwise, die.
			--kernelAsyncRunnersAvailable;
			libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

			if (permanent) {
				continue;
			} else {
				break;
			}
		}

		// we're going to perform some work; we're no longer available
		--kernelAsyncRunnersAvailable;

		auto func = kernelAsyncRunnerQueue.front();
		kernelAsyncRunnerQueue.pop();

		libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

		// perform the work
		func();
	} while (permanent);

	self = nullptr;
	DarlingServer::Thread::currentThread()->terminate();
	__builtin_unreachable();
};

void DarlingServer::Thread::kernelAsync(std::function<void()> fn) {
	static bool inited = []() {
		kernelAsyncRunnerQueueSempahore = dtape_semaphore_create(Process::kernelProcess()->_dtapeTask, 0);
		return true;
	}();

	libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
	kernelAsyncRunnerQueue.push(fn);
	if (kernelAsyncRunnersAvailable == 0) {
		// we need to get some work done, but there are no workers available.
		// if we have less workers than the max permanent number of workers,
		// let's spawn a permanent worker. otherwise, just spawn a temporary worker.
		auto thread = std::make_shared<Thread>(KernelThreadConstructorTag());
		auto permanent = permanentKernelAsyncRunners.size() < MAX_PERMANENT_KERNEL_RUNNERS;
		thread->startKernelThread(std::bind(kernelAsyncRunnerThreadWorker, permanent, thread));
		if (permanent) {
			permanentKernelAsyncRunners.push_back(std::move(thread));
		}
	}
	libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

	// increment the semaphore to let workers know there's work available.
	dtape_semaphore_up(kernelAsyncRunnerQueueSempahore);
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

void DarlingServer::Thread::loadStateFromUser(dserver_rpc_architecture_t callerArchitecture, uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_load_state_from_user(_dtapeThread, callerArchitecture, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

void DarlingServer::Thread::saveStateToUser(dserver_rpc_architecture_t callerArchitecture, uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_save_state_to_user(_dtapeThread, callerArchitecture, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

int DarlingServer::Thread::pendingSignal() const {
	std::shared_lock lock(_rwlock);
	return (_interrupts.empty()) ? 0 : _interrupts.top().signal;
};

int DarlingServer::Thread::setPendingSignal(int signal) {
	std::unique_lock lock(_rwlock);
	int pendingSignal;
	if (_interrupts.empty()) {
		throw std::runtime_error("Can't set pending signal with no active interrupts");
	} else {
		pendingSignal = _interrupts.top().signal;
		_interrupts.top().signal = signal;
	}
	return pendingSignal;
};

void DarlingServer::Thread::processSignal(int bsdSignalNumber, int linuxSignalNumber, int code, uintptr_t signalAddress, dserver_rpc_architecture_t callerArchitecture, uintptr_t threadStateAddress, uintptr_t floatStateAddress, const std::optional<dtape_exception_state_t>& exceptionState) {
	loadStateFromUser(callerArchitecture, threadStateAddress, floatStateAddress);
	dtape_thread_set_exception_state(_dtapeThread, exceptionState ? &*exceptionState : nullptr);

	{
		std::unique_lock lock(_rwlock);
		_interrupts.top().signal = 0;
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

	saveStateToUser(callerArchitecture, threadStateAddress, floatStateAddress);
};

void DarlingServer::Thread::handleSignal(int signal) {
	std::unique_lock lock(_rwlock);
	if (_processingSignal) {
		_interrupts.top().signal = signal;
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
 * in order to perform an S2C call, however, the target thread MUST be waiting for a message from the server.
 * thus, when we want to perform an S2C call on a thread that isn't waiting for a message, we send it a real-time signal
 * to ask it to execute the S2C call. the signal is handled with the normal wrappers (interrupt_enter and interrupt_exit)
 * to properly handle the case when we may be accidentally interrupting an ongoing call in the thread (since we may have raced
 * with thread trying to perform a server call).
 */

static DarlingServer::Log s2cLog("s2c");

std::optional<DarlingServer::Message> DarlingServer::Thread::_s2cPerform(Message&& call, dserver_s2c_msgnum_t expectedReplyNumber, size_t expectedReplySize, int& outErrno, size_t staleMappingLength, bool staleMappingReusable) {
	std::optional<Message> reply = std::nullopt;
	bool usingInterrupt = false;

	// an interrupted wait means a signal is being delivered to the current thread (or it is being suspended or killed).
	// whatever call it is making is abandoned; let that call be restarted once the signal has been handled
	// (see the `current_thread_take_s2c_interrupted` duct-tape hook) instead of failing it because of the signal.
	auto abandonedForInterrupt = [&]() {
		currentThread()->_s2cInterrupted = true;
		outErrno = EINTR;
		return std::nullopt;
	};

	// a failed or interrupted S2C call must never take the server down: every failure is reported to the caller
	// as `std::nullopt` plus an errno value, and the caller turns that into an error for the single operation.

	// at least for now, in order to wait for the S2C reply, we need the calling thread to be a microthread,
	// so that waiting on the duct-taped semaphore will work
	if (!currentThread()) {
		s2cLog.error() << *this << ": S2C call attempted outside of a microthread" << s2cLog.endLog;
		outErrno = EINVAL;
		return std::nullopt;
	}

	// a call that is being finished while its thread enters a signal handler (see `_handleInterruptEnterForCurrentThread`)
	// must not wait: a suspension in that state isn't resumed correctly. its S2C waits have just been interrupted anyway,
	// so don't send a new call (EAGAIN: nothing was sent); the call is restarted after the handler instead.
	auto finishingInterruptedCall = [&]() {
		if (!currentThread()->_interruptedForSignal) {
			return false;
		}
		currentThread()->_s2cInterrupted = true;
		outErrno = EAGAIN;
		return true;
	};

	if (finishingInterruptedCall()) {
		return std::nullopt;
	}

	// first get rid of what abandoned mmap calls left behind
	_s2cUndoStaleMappings();

	// (the signal may have arrived while doing that)
	if (finishingInterruptedCall()) {
		return std::nullopt;
	}

	// make sure we're the only one performing an S2C call on this thread
	if (!dtape_semaphore_down_simple(_s2cPerformSempahore)) {
		// got interrupted while waiting
		return abandonedForInterrupt();
	}

	s2cLog.debug() << *this << ": Going to perform S2C call" << s2cLog.endLog;

	{
		std::unique_lock lock(_rwlock);

		if (_s2cStaleReplyPending) {
			// an earlier call was abandoned and the client hasn't answered it yet.
			// it may be in the middle of servicing it (e.g. it was interrupted by a signal while doing so), in which case
			// it would answer a new call first; and if we're running on its behalf, it can't answer the old call until we return.
			// so neither sending a new call nor waiting for the old reply is safe; fail this call instead.
			lock.unlock();
			s2cLog.debug() << *this << ": Previous S2C call still unanswered; not sending another one" << s2cLog.endLog;
			dtape_semaphore_up(_s2cPerformSempahore);
			if (currentThread().get() == this) {
				// that call was abandoned for a signal, and the client answers it before it gets the reply to this call;
				// a call that can be restarted is better restarted (it finds the client caught up) than failed
				_s2cInterrupted = true;
			}
			outErrno = EAGAIN;
			return std::nullopt;
		}

		if (!_activeCall) {
			// signal the thread that we want to perform an S2C call and wait for it to give us the green light
			lock.unlock();
			s2cLog.debug() << *this << ": Sending S2C signal" << s2cLog.endLog;
			usingInterrupt = true;
			sendSignal(LINUX_SIGRTMIN + 1);
			if (!dtape_semaphore_down_simple(_s2cInterruptEnterSemaphore)) {
				// got interrupted while waiting.
				// the thread will still run its S2C handler; make sure it isn't kept waiting for us.
				lock.lock();
				if (_s2cInterruptEntered) {
					// the handler already got as far as giving us the green light (it raises the semaphore right after setting the flag),
					// so it is now waiting for us to let it go. take the green light and let it go.
					_s2cInterruptEntered = false;
					lock.unlock();
					while (!dtape_semaphore_down_simple(_s2cInterruptEnterSemaphore)) {
						// the handler raises the semaphore without blocking first, so this wait is short; just retry
					}
					dtape_semaphore_up(_s2cInterruptExitSemaphore);
				} else {
					// the handler hasn't got there yet; it checks this count under the same lock and won't wait for us
					++_s2cInterruptAbandoned;
					lock.unlock();
				}
				dtape_semaphore_up(_s2cPerformSempahore);
				return abandonedForInterrupt();
			}
			s2cLog.debug() << *this << ": Got green light to perform S2C call" << s2cLog.endLog;
			lock.lock();
			_s2cInterruptEntered = false;
		} else if (currentThread().get() != this) {
			// we have an active call, so the client is waiting for a reply and is able to perform an S2C call,
			// but we're not the active thread. thus, in order to guarantee the client doesn't receive a reply
			// and stop waiting before we get a chance to perform our S2C call, let's make sure replies are deferred.
			_deferReplyForS2C = true;
		}

		call.setAddress(_address);
		_s2cCallInFlight = true;
	}

	s2cLog.debug() << *this << ": Going to send S2C message" << s2cLog.endLog;

	// send the call
	Server::sharedInstance().sendMessage(std::move(call));

	// now let's wait for the reply.
	// the semaphore count is only a wakeup; the reply itself lives in `_s2cReply`, so keep waiting
	// if we were woken without one (e.g. for a reply we already took after an interrupted wait).
	while (true) {
		bool interrupted = !dtape_semaphore_down_simple(_s2cReplySempahore);

		std::unique_lock lock(_rwlock);

		if (_s2cReply) {
			reply = std::move(_s2cReply);
			_s2cReply = std::nullopt;
		} else if (interrupted) {
			// the client has been asked to perform the call (and will still do so), but we're not going to wait for it.
			// remember that its reply is stale when it arrives, so that it isn't mistaken for the reply to a later call.
			_s2cStaleReplyPending = true;
			_s2cStaleReplyUsedInterrupt = usingInterrupt;
			_s2cStaleMappingLength = staleMappingLength;
			_s2cStaleMappingReusable = staleMappingReusable;
			_s2cCallInFlight = false;

			// if we had replies deferred, release them: the client handles the S2C call first (it was sent first),
			// so it doesn't matter that the reply to the interrupted call is still to come.
			if (_deferReplyForS2C) {
				_deferReplyForS2C = false;
				if (_deferredReply) {
					Server::sharedInstance().sendMessage(std::move(*_deferredReply));
					_deferredReply = std::nullopt;
				}
			}

			lock.unlock();
			s2cLog.debug() << *this << ": S2C reply wait interrupted; reply will be discarded" << s2cLog.endLog;
			dtape_semaphore_up(_s2cPerformSempahore);
			return abandonedForInterrupt();
		} else {
			continue;
		}

		_s2cCallInFlight = false;

		// if we had replies deferred, now's the time to send them
		if (_deferReplyForS2C) {
			_deferReplyForS2C = false;
			if (_deferredReply) {
				Server::sharedInstance().sendMessage(std::move(*_deferredReply));
				_deferredReply = std::nullopt;
			}
		}
		break;
	}

	s2cLog.debug() << *this << ": Received S2C reply" << s2cLog.endLog;
	s2cLog.debug() << *this << ": Done performing S2C call" << s2cLog.endLog;

	// we're done performing the call; allow others to have a chance at performing an S2C call on this thread
	dtape_semaphore_up(_s2cPerformSempahore);

	if (usingInterrupt) {
		// if we used the S2C signal to perform the call, then the s2c_perform call is currently waiting for us to finish;
		// let it know that we're done
		s2cLog.debug() << *this << ": Allowing thread to resume from S2C interrupt" << s2cLog.endLog;
		dtape_semaphore_up(_s2cInterruptExitSemaphore);
	}

	// partially validate the reply.
	// a malformed reply can only come from a misbehaving client, so it fails this one call (it is not fatal to the server).

	if (reply->data().size() != expectedReplySize) {
		s2cLog.error() << *this << ": Invalid S2C reply: unexpected size " << reply->data().size() << " (expected " << expectedReplySize << ")" << s2cLog.endLog;
		outErrno = EPROTO;
		return std::nullopt;
	}

	auto replyHeader = reinterpret_cast<dserver_s2c_replyhdr_t*>(reply->data().data());
	if (replyHeader->s2c_number != expectedReplyNumber) {
		s2cLog.error() << *this << ": Invalid S2C reply: unexpected S2C reply number" << s2cLog.endLog;
		outErrno = EPROTO;
		return std::nullopt;
	}

	return std::move(*reply);
};

void DarlingServer::Thread::_s2cNoteStaleMapping(const Message& staleReply, size_t length, bool reusable) {
	if (staleReply.data().size() != sizeof(dserver_s2c_reply_mmap_t)) {
		return;
	}

	auto reply = reinterpret_cast<const dserver_s2c_reply_mmap_t*>(staleReply.data().data());
	if (reply->header.s2c_number != dserver_s2c_msgnum_mmap || reply->errno_result != 0 || reply->address == (uint64_t)(uintptr_t)MAP_FAILED) {
		return;
	}

	std::unique_lock lock(_rwlock);
	(reusable ? _s2cReusableStaleMappings : _s2cStaleMappings).emplace_back(reply->address, length);
};

uintptr_t DarlingServer::Thread::_takeReusableStaleMapping(size_t length) {
	std::unique_lock lock(_rwlock);
	for (auto it = _s2cReusableStaleMappings.begin(); it != _s2cReusableStaleMappings.end(); ++it) {
		if (it->second == length) {
			uintptr_t address = it->first;
			_s2cReusableStaleMappings.erase(it);
			return address;
		}
	}
	return 0;
};

void DarlingServer::Thread::_s2cUndoStaleMappings() {
	std::vector<std::pair<uintptr_t, size_t>> mappings;

	{
		std::unique_lock lock(_rwlock);
		mappings.swap(_s2cStaleMappings);
		mappings.insert(mappings.end(), _s2cReusableStaleMappings.begin(), _s2cReusableStaleMappings.end());
		_s2cReusableStaleMappings.clear();
	}

	// nobody owns these mappings: the calls that made them failed (or were restarted) and the addresses were never handed out
	for (size_t i = 0; i < mappings.size(); ++i) {
		int err = 0;
		if (_munmap(mappings[i].first, mappings[i].second, err) < 0 && (err == EAGAIN || err == EINVAL)) {
			// the call wasn't sent; try again next time
			std::unique_lock lock(_rwlock);
			_s2cStaleMappings.insert(_s2cStaleMappings.end(), mappings.begin() + i, mappings.end());
			break;
		}
	}
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

	Message callMessage(sizeof(dserver_s2c_call_mmap_t), (fd < 0) ? 0 : 1);
	auto call = reinterpret_cast<dserver_s2c_call_mmap_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_mmap;
	call->address = address;
	call->length = length;
	call->protection = protection;
	call->flags = flags;
	call->fd = (fd < 0) ? -1 : 0;
	call->offset = offset;

	if (fd >= 0) {
		auto dupfd = dup(fd);
		if (dupfd < 0) {
			outErrno = errno;
			return (uintptr_t)MAP_FAILED;
		}
		callMessage.pushDescriptor(dupfd);
	}

	s2cLog.debug() << "Performing _mmap with address=" << call->address << ", length=" << call->length << ", protection=" << call->protection << ", flags=" << call->flags << ", fd=" << call->fd << " (" << fd << ")" << ", offset=" << call->offset << s2cLog.endLog;

	// if this call is abandoned, the mapping it makes is unmapped again, unless it replaces memory at a fixed address
	// (that range belongs to whoever asked for it, and a restarted call maps it again)
	// (fresh read-write anonymous memory placed by the client may be taken by a restarted call instead; see `_s2cReusableStaleMappings`)
	bool reusable = address == 0 && fd < 0 && protection == (PROT_READ | PROT_WRITE) && flags == (MAP_PRIVATE | MAP_ANONYMOUS);
	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_mmap, sizeof(dserver_s2c_reply_mmap_t), outErrno, (flags & MAP_FIXED) ? 0 : length, reusable);
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_mmap call interrupted" << s2cLog.endLog;
		return (uintptr_t)MAP_FAILED;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
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

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_munmap, sizeof(dserver_s2c_reply_munmap_t), outErrno);
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_munmap call interrupted" << s2cLog.endLog;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_munmap_t*>(replyMessage.data().data());

	s2cLog.debug() << "_munmap returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

int DarlingServer::Thread::_mprotect(uintptr_t address, size_t length, int protection, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_mprotect_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_mprotect_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_mprotect;
	call->address = address;
	call->length = length;
	call->protection = protection;

	s2cLog.debug() << "Performing _mprotect with address=" << call->address << ", length=" << call->length << ", protection=" << call->protection << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_mprotect, sizeof(dserver_s2c_reply_mprotect_t), outErrno);
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_mprotect call interrupted" << s2cLog.endLog;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_mprotect_t*>(replyMessage.data().data());

	s2cLog.debug() << "_mprotect returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

int DarlingServer::Thread::_msync(uintptr_t address, size_t size, int sync_flags, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_msync_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_msync_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_msync;
	call->address = address;
	call->size = size;
	call->sync_flags = sync_flags;

	s2cLog.debug() << "Performing _msync with address=" << call->address << ", size=" << call->size << ", sync_flags=" << call->sync_flags << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_msync, sizeof(dserver_s2c_reply_msync_t), outErrno);
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_msync call interrupted" << s2cLog.endLog;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_msync_t*>(replyMessage.data().data());

	s2cLog.debug() << "_msync returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

uintptr_t DarlingServer::Thread::allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite) {
	int err = 0;
	// As XNU, set no memory aside when mapping: pages are committed as they
	// are touched (see the BSD mmap() in libsystem_kernel; test:
	// mmap-large-anonymous.c in Darling's xnu tests).
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	if (fixed && overwrite) {
		flags |= MAP_FIXED;
	} else if (fixed) {
		flags |= MAP_FIXED_NOREPLACE;
	}
	auto result = _mmap(addressHint, pageCount * sysconf(_SC_PAGESIZE), protection, flags, -1, 0, err);
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

uintptr_t DarlingServer::Thread::mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite) {
	int err = 0;
	int flags = MAP_SHARED;
	if (fixed && overwrite) {
		flags |= MAP_FIXED;
	} else if (fixed) {
		flags |= MAP_FIXED_NOREPLACE;
	}
	auto result = _mmap(addressHint, pageCount * sysconf(_SC_PAGESIZE), protection, flags, fd, pageOffset * sysconf(_SC_PAGESIZE), err);
	if (result == (uintptr_t)MAP_FAILED) {
		throw std::system_error(err, std::generic_category(), "S2C mmap call failed");
	}
	return result;
};

void DarlingServer::Thread::changeProtection(uintptr_t address, size_t pageCount, int protection) {
	int err = 0;
	if (_mprotect(address, pageCount * sysconf(_SC_PAGESIZE), protection, err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C mprotect call failed");
	}
};

void DarlingServer::Thread::syncMemory(uintptr_t address, size_t size, int sync_flags) {
	int err = 0;
	if (_msync(address, size, sync_flags, err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C msync call failed");
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

void DarlingServer::Thread::_deferLocked(bool wait, std::unique_lock<std::shared_mutex>& lock) {
	if (_deferralState == DeferralState::NotDeferred) {
		_deferralState = DeferralState::DeferredNotPending;
	}

	if (wait) {
		_runningCondvar.wait(lock, [&]() {
			return !_running;
		});
	}
};

void DarlingServer::Thread::defer(bool wait) {
	std::unique_lock lock(_rwlock);
	_deferLocked(wait, lock);
};

void DarlingServer::Thread::_undeferLocked(std::unique_lock<std::shared_mutex>& lock) {
	DeferralState previousDeferralState;

	previousDeferralState = _deferralState;
	_deferralState = DeferralState::NotDeferred;

	if (previousDeferralState == DeferralState::DeferredPending) {
		Server::sharedInstance().scheduleThread(shared_from_this());
	}
};

void DarlingServer::Thread::undefer() {
	std::unique_lock lock(_rwlock);
	_undeferLocked(lock);
};

uint32_t* DarlingServer::Thread::bsdReturnValuePointer() {
	return &_bsdReturnValue;
};

void DarlingServer::Thread::logToStream(Log::Stream& stream) const {
	stream << "[T:" << _tid << "(" << _nstid << ")]";
};

void DarlingServer::Thread::pushCallReply(std::shared_ptr<Call> expectedCall, Message&& reply) {
	// the call is done, so the thread is about to return to user space.
	// this must happen before the reply is sent (or the thread could be marked again in user space before we clear the abort)
	// and without `_rwlock` held (the thread lock is taken before `_rwlock` elsewhere).
	// the duct-taped thread cannot be released while the call is still active.
	if (expectedCall && _dtapeThread) {
		dtape_thread_returning_to_user(_dtapeThread);
	}

	std::unique_lock lock(_rwlock);

	if (expectedCall) {
		_deactivateCallLocked(expectedCall);
	}

	if (_interruptedForSignal) {
		_interrupts.top().savedReplies.push_back(std::move(reply));
	} else if (_deferReplyForS2C) {
		_deferredReply = std::move(reply);
	} else if (!_dead) {
		Server::sharedInstance().sendMessage(std::move(reply));
	}
};

bool DarlingServer::Thread::getStats(char* name, size_t nameSize, uint64_t& userTimeNs, uint64_t& systemTimeNs) const {
	auto process = this->process();
	if (!process || isDead() || nameSize == 0) {
		return false;
	}

	// the threads of the kernel task are not threads of Linux, so Linux has no times for them
	// (the CPU time of the server is accounted to the task, see Process::cpuTimes())
	if (process == Process::kernelProcess()) {
		userTimeNs = 0;
		systemTimeNs = 0;
		name[0] = '\0';
		return true;
	}

	std::string base = "/proc/" + std::to_string(process->id()) + "/task/" + std::to_string(id());
	std::string line;

	{
		std::ifstream file(base + "/stat");
		if (!std::getline(file, line)) {
			return false;
		}
	}

	// the command name is parenthesized and may itself contain spaces and parentheses, so parse after the last ')'.
	// the fields after it start with the state (field 3); utime and stime are fields 14 and 15, in clock ticks.
	auto endOfComm = line.rfind(')');
	if (endOfComm == std::string::npos) {
		return false;
	}

	std::istringstream fields(line.substr(endOfComm + 1));
	std::string field;
	unsigned long long utime = 0;
	unsigned long long stime = 0;
	for (int index = 3; index <= 15; ++index) {
		if (!(fields >> field)) {
			return false;
		}
		if (index == 14) {
			utime = std::strtoull(field.c_str(), nullptr, 10);
		} else if (index == 15) {
			stime = std::strtoull(field.c_str(), nullptr, 10);
		}
	}

	long ticksPerSecond = sysconf(_SC_CLK_TCK);
	if (ticksPerSecond <= 0) {
		ticksPerSecond = 100;
	}
	userTimeNs = utime * (1000000000ULL / ticksPerSecond);
	systemTimeNs = stime * (1000000000ULL / ticksPerSecond);

	std::string comm;
	{
		std::ifstream file(base + "/comm");
		if (!std::getline(file, comm)) {
			return false;
		}
	}
	std::strncpy(name, comm.c_str(), nameSize - 1);
	name[nameSize - 1] = '\0';

	return true;
};

DarlingServer::Thread::RunState DarlingServer::Thread::getRunState() const {
	auto process = this->process();
	if (!process || isDead()) {
		return RunState::Dead;
	}

	// the threads of the kernel task are not threads of Linux: they run when the server has work for them
	if (process == Process::kernelProcess()) {
		return RunState::Interruptible;
	}

	std::ifstream file("/proc/" + std::to_string(process->id()) + "/task/" + std::to_string(id()) + "/stat");
	std::string line;
	if (!std::getline(file, line)) {
		return RunState::Dead;
	}

	auto endOfComm = line.find(')');
	if (endOfComm == std::string::npos) {
		return RunState::Dead;
	}

	if (line.size() <= endOfComm + 2) {
		return RunState::Dead;
	}

	switch (line[endOfComm + 2]) {
		case 'R':
			return RunState::Running;
		case 'S':
			return RunState::Interruptible;
		case 'D':
			return RunState::Uninterruptible;
		case 'T':
			return RunState::Stopped;
		default:
			return RunState::Dead;
	}
};

void DarlingServer::Thread::waitWhileUserSuspended(dserver_rpc_architecture_t callerArchitecture, uintptr_t threadStateAddress, uintptr_t floatStateAddress) {
	loadStateFromUser(callerArchitecture, threadStateAddress, floatStateAddress);
	dtape_thread_wait_while_user_suspended(_dtapeThread);
	try {
		saveStateToUser(callerArchitecture, threadStateAddress, floatStateAddress);
	} catch (std::system_error e) {
		// if we fail to save the state back to the process, that likely means the process died or was killed while waiting.
		// it's nothing to worry about. just log it and move on.
		threadLog.warning() << *this << ": failed to save state back to user in waitWhileUserSuspended: " << e.code() << " (" << e.what() << ")" << threadLog.endLog;
	}
};

void DarlingServer::Thread::sendSignal(int signal) const {
	if (isDead()) {
		return;
	}
	if (_process) {
		if (syscall(SYS_tgkill, _process->id(), id(), signal) < 0) {
			int code = errno;
			throw std::system_error(code, std::generic_category());
		}
	} else {
		throw std::system_error(ESRCH, std::generic_category());
	}
};

void DarlingServer::Thread::jumpToResume(void* stack, size_t stackSize) {
#if DSERVER_ASAN
	__sanitizer_start_switch_fiber(&_asanOldFakeStack, stack, stackSize);
#endif
	setcontext(&_resumeContext);
	__builtin_unreachable();
};

void DarlingServer::Thread::notifyDead() {
	bool canRelease = false;

	{
		std::unique_lock lock(_rwlock);
		if (_dead) {
			return;
		}

		threadLog.info() << *this << ": thread dying" << threadLog.endLog;
		_dead = true;

		// the thread's TSD may be unmapped from now on
		_cancelMarkedAddress = 0;

		if (!_activeCall) {
			// if we have no active call, we won't ever need to run again,
			// so set `_terminating` to make sure that doesn't happen
			_terminating = true;
			canRelease = true;
		}
	}

	// keep ourselves alive until the duct-taped context is done
	_selfReference = shared_from_this();

	dtape_thread_dying(_dtapeThread);

	if (canRelease) {
		_scheduleRelease();
	} else {
		resume();
	}

	threadRegistry().unregisterEntry(shared_from_this());
};

bool DarlingServer::Thread::isDead() const {
	std::shared_lock lock(_rwlock);
	return _dead;
};

void DarlingServer::Thread::_dispose() {
	threadLog.debug() << *this << ": dispose thread context" << threadLog.endLog;
	_selfReference = nullptr;
};

void DarlingServer::Thread::_scheduleRelease() {
	// schedule the duct-taped thread to be released
	// dtape_thread_release needs a microthread context, so we call it within a kernel microthread
	threadLog.debug() << *this << ": scheduling release" << threadLog.endLog;
	kernelAsync([self = shared_from_this()]() {
		if (self->_s2cPerformSempahore) {
			dtape_semaphore_destroy(self->_s2cPerformSempahore);
			self->_s2cPerformSempahore = nullptr;
		}
		if (self->_s2cReplySempahore) {
			dtape_semaphore_destroy(self->_s2cReplySempahore);
			self->_s2cReplySempahore = nullptr;
		}
		if (self->_s2cInterruptEnterSemaphore) {
			dtape_semaphore_destroy(self->_s2cInterruptEnterSemaphore);
			self->_s2cInterruptEnterSemaphore = nullptr;
		}
		if (self->_s2cInterruptExitSemaphore) {
			dtape_semaphore_destroy(self->_s2cInterruptExitSemaphore);
			self->_s2cInterruptExitSemaphore = nullptr;
		}
		dtape_thread_release(self->_dtapeThread);
		self->_dtapeThread = nullptr;
	});
};

void DarlingServer::Thread::_handleInterruptEnterForCurrentThread(bool transparent) {
	// FIXME: this currently does not work properly if the thread was suspended waiting for a lock
	Thread* self = currentThread().get();
	auto& interrupt = self->_interrupts.top();

	{
		std::unique_lock lock(self->_rwlock);

		// replies the client pushed back before this interrupt was entered were sent before anything saved since
		auto& savedReplies = interrupt.savedReplies;
		while (!self->_pendingSavedReplies.empty()) {
			savedReplies.push_front(std::move(self->_pendingSavedReplies.back()));
			self->_pendingSavedReplies.pop_back();
		}

		self->_interruptedForSignal = true;

		interrupt.continuation = std::exchange(self->_interruptedContinuation, nullptr);
	}

	dtape_thread_sigexc_enter(self->_dtapeThread, transparent);

	self->_didSyscallReturnDuringInterrupt = false;
	getcontext(&self->_syscallReturnHereDuringInterrupt);

	if (!self->_didSyscallReturnDuringInterrupt) {
		if (interrupt.continuation) {
			interrupt.continuation();
		} else if (interrupt.interruptedCall) {
			self->_handlingInterruptedCall = true;
			self->_pendingCallOverride = true;
			self->jumpToResume(interrupt.savedStack.base, interrupt.savedStack.size);
		}
	} else if (self->_handlingInterruptedCall) {
#if DSERVER_ASAN
		const void* dummy;
		size_t dummy2;
		__sanitizer_finish_switch_fiber(nullptr, &dummy, &dummy2);
#endif

		self->_handlingInterruptedCall = false;
		self->_pendingCallOverride = false;
	}

	interrupt.continuation = nullptr;

	{
		std::unique_lock lock(self->_rwlock);

		if (interrupt.savedStack.isValid()) {
			stackPool.free(interrupt.savedStack);
		}
		interrupt.savedContinuation = nullptr;

		self->_interruptedForSignal = false;
		interrupt.interruptedCall = nullptr;
	}

	dtape_thread_sigexc_enter2(self->_dtapeThread);
};
