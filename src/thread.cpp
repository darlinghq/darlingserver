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

static thread_local std::shared_ptr<DarlingServer::Thread> currentThreadVar = nullptr;
static thread_local bool returningToThreadTop = false;
static thread_local ucontext_t backToThreadTopContext;
static thread_local libsimple_lock_t* unlockMeWhenSuspending = nullptr;

/**
 * Our microthreads use cooperative multitasking, so we don't really use interrupts per-se.
 * Rather, this is an indication to our cooperative scheduler that the microthread is doing something and
 * expects to continue to have control of the executing thread. If it calls a function/method that
 * would cause it to relinquish control of the thread, this should be considered an error.
 *
 * This is primarily of use for debugging duct-tape code and ensuring certain assumptions made in the duct-tape code hold true.
 */
static thread_local uint64_t interruptDisableCount = 0;

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
	_stack = mmap(NULL, _stackSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (_stack == MAP_FAILED) {
		throw std::system_error(errno, std::generic_category());
	}

	// NOTE: it's okay to use raw `this` without a shared pointer because the duct-taped thread will always live for less time than this Thread instance
	_dtapeThread = dtape_thread_create(process->_dtapeTask, _nstid, this);
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
	_stack = mmap(NULL, _stackSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (_stack == MAP_FAILED) {
		throw std::system_error(errno, std::generic_category());
	}

	_dtapeThread = dtape_thread_create(Process::kernelProcess()->_dtapeTask, _nstid, this);
};

void DarlingServer::Thread::registerWithProcess() {
	auto process = _process.lock();
	std::unique_lock lock(process->_rwlock);
	process->_threads.push_back(shared_from_this());
};

DarlingServer::Thread::~Thread() noexcept(false) {
	if (munmap(_stack, _stackSize) < 0) {
		throw std::system_error(errno, std::generic_category());
	}

	auto process = _process.lock();
	if (!process) {
		// the process is unregistering us
		return;
	}

	std::unique_lock lock(process->_rwlock);
	auto it = process->_threads.begin();
	while (it != process->_threads.end()) {
		if (auto thread = it->lock()) {
			if (thread.get() == this) {
				break;
			}
		}
	}
	if (it == process->_threads.end()) {
		throw std::runtime_error("Thread was not registered with Process");
	}
	process->_threads.erase(it);

	dtape_thread_destroy(_dtapeThread);
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
	currentThreadVar->pendingCall()->processCall();
};

void DarlingServer::Thread::microthreadContinuation() {
	auto callback = currentThreadVar->_continuationCallback;
	currentThreadVar->_continuationCallback = nullptr;
	callback(currentThreadVar->_dtapeThread);
};

void DarlingServer::Thread::doWork() {
	// NOTE: this method MUST NOT use any local variables that require destructors.
	//       this method is actually major UB because the compiler is free to do whatever it likes with the stack,
	//       but we know what reasonable compilers (i.e. GCC and Clang) do with it and we're specifically targeting Clang, so it's okay for us.

	_rwlock.lock();

	if (_running) {
		// this is probably an error
		microthreadLog.warning() << "Attempt to re-run already running microthread on another thread" << microthreadLog.endLog;
		_rwlock.unlock();
		return;
	}

	_running = true;
	currentThreadVar = shared_from_this();
	dtape_thread_entering(_dtapeThread);

	returningToThreadTop = false;
	_rwlock.unlock();

	getcontext(&backToThreadTopContext);

	if (returningToThreadTop) {
		// someone jumped back to the top of the microthread
		// (that means either the microthread has been suspended or it has finished)
		goto doneWorking;
	} else {
		returningToThreadTop = true;

		_rwlock.lock();

		if (_suspended) {
			// we were in the middle of processing a call and we need to resume now
			_suspended = false;
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
	dtape_thread_exiting(_dtapeThread);
	currentThreadVar = nullptr;
	_running = false;
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
	return;
};

void DarlingServer::Thread::suspend(dtape_thread_continuation_callback_f continuationCallback, libsimple_lock_t* unlockMe) {
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
	_rwlock.lock_shared();
	if (!_suspended) {
		// maybe we should throw an error here?
		return;
	}
	_rwlock.unlock_shared();

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

	if (currentThreadVar.get() != this) {
		throw std::runtime_error("terminate() called on non-current kernel thread (currently unsupported)");
	}

	_rwlock.lock();
	_terminating = true;
	_rwlock.unlock();
	suspend();

	throw std::runtime_error("terminate() on current kernel thread returned");
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::currentThread() {
	return currentThreadVar;
};

void DarlingServer::Thread::_startKernelThread(dtape_thread_continuation_callback_f startupCallback) {
	_continuationCallback = startupCallback;
	_suspended = true;
	getcontext(&_resumeContext);
	_resumeContext.uc_stack.ss_sp = _stack;
	_resumeContext.uc_stack.ss_size = _stackSize;
	_resumeContext.uc_stack.ss_flags = 0;
	_resumeContext.uc_link = &backToThreadTopContext;
	makecontext(&_resumeContext, microthreadContinuation, 0);

	resume();
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
