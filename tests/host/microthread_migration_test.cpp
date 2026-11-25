#ifdef DSERVER_ASAN
#undef DSERVER_ASAN
#endif
// This test exercises optimized migration without ASan's separate fiber protocol.
#define DSERVER_ASAN 0
#include "microthread_stubs.hpp"
#include <atomic>
#include <chrono>
#include MICROTHREAD_INC

using DarlingServer::Call;
using DarlingServer::Thread;

class Gate {
	std::mutex mutex;
	std::condition_variable cv;
	bool ready = false;
public:
	void release() {
		std::lock_guard lock(mutex);
		ready = true;
		cv.notify_one();
	}
	void wait() {
		std::unique_lock lock(mutex);
		check(cv.wait_for(lock, std::chrono::seconds(5), [&] { return ready; }),
			"host handshake completes");
	}
};

enum class Mode { Call, Continuation, Syscall, Replacement, Unlock, Interrupt, InterruptedContinuation };
struct Scenario {
	Mode mode;
	Gate decoyReady, releaseDecoy;
	std::weak_ptr<int> token;
	libsimple_lock_t lock;
	bool completed = false;
};
static Scenario* scenario;

static std::function<void()> replacement() {
	auto token = std::make_shared<int>(1);
	scenario->token = token;
	return [token] {
		check(!scenario->token.expired(), "replacement owns its captures while running");
		scenario->completed = true;
	};
}

static void migratingBody() {
	auto* self = Thread::currentThread().get();
	if (scenario->mode == Mode::Replacement) {
		self->suspend(replacement());
		check(false, "a replaced continuation is never resumed");
	}
	self->suspend(nullptr, scenario->mode == Mode::Unlock ? &scenario->lock : nullptr);
	check(Thread::currentThread().get() == self, "migration preserves the current microthread");
	if (scenario->mode == Mode::Continuation || scenario->mode == Mode::Interrupt ||
		scenario->mode == Mode::InterruptedContinuation)
		check(!scenario->token.expired(), "a suspended continuation survives a decoy microthread");
	scenario->completed = true;
	if (scenario->mode == Mode::Syscall || scenario->mode == Mode::Interrupt)
		Thread::syscallReturn(17);
}

static void run(Mode mode) {
	Scenario state{mode};
	scenario = &state;
	auto thread = std::make_shared<Thread>();
	auto decoy = std::make_shared<Thread>();
	auto call = std::make_shared<Call>();
	call->body = migratingBody;
	if (mode == Mode::Continuation || mode == Mode::Interrupt || mode == Mode::InterruptedContinuation) {
		auto token = std::make_shared<int>(1);
		state.token = token;
		if (mode != Mode::Interrupt) {
			thread->setupKernelThread([token] { migratingBody(); });
			if (mode == Mode::InterruptedContinuation)
				thread->_activeCall = call;
		} else {
			thread->_interruptedContinuation = [token] { migratingBody(); };
			thread->_interrupts.emplace();
			thread->_interrupts.top().interruptedCall = call;
			call->body = [] { Thread::_handleInterruptEnterForCurrentThread(false); };
			thread->_pendingCall = call;
		}
	} else {
		thread->_pendingCall = call;
	}
	decoy->_pendingCall = std::make_shared<Call>();
	decoy->_pendingCall->body = [&] {
		state.decoyReady.release();
		state.releaseDecoy.wait();
	};

	std::thread origin([&] {
		state.lock.owner = pthread_self();
		thread->doWork();
		check(thread->_suspended, "first host returns after suspension");
		decoy->doWork();
	});
	std::thread destination([&] {
		state.decoyReady.wait();
		if (mode == Mode::InterruptedContinuation) {
			thread->_pendingCall = std::make_shared<Call>();
			thread->_pendingCall->kind = Call::Number::InterruptEnter;
			thread->_pendingCall->body = [] { Thread::_handleInterruptEnterForCurrentThread(false); };
		}
		thread->doWork();
		check(state.completed, "resumed work completes on the second host");
		if (mode == Mode::Continuation || mode == Mode::Replacement || mode == Mode::Interrupt ||
			mode == Mode::InterruptedContinuation)
			check(state.token.expired(), "completed continuation releases its captures");
		if (mode == Mode::Syscall || mode == Mode::Interrupt)
			check(call->reply == 17, "syscall return sends the requested result");
		if (mode == Mode::Unlock)
			check(state.lock.unlocks == 1, "suspension releases its lock exactly once");
		state.releaseDecoy.release();
	});
	destination.join();
	origin.join();
	std::printf("PASS migration scenario %d\n", static_cast<int>(mode));
}

static void runLockHandoff() {
	Gate wakeDestination, destinationExiting, originReturned;
	std::atomic<bool> onDestination = false;
	libsimple_lock_t first, second;
	auto thread = std::make_shared<Thread>();
	thread->_pendingCall = std::make_shared<Call>();
	thread->_pendingCall->body = [&] {
		thread->suspend(nullptr, &first);
		thread->suspend(nullptr, &second);
	};
	thread->onExit = [&] {
		if (onDestination) {
			destinationExiting.release();
			originReturned.wait();
		}
	};
	first.afterUnlock = [&] {
		wakeDestination.release();
		destinationExiting.wait();
	};
	std::thread origin([&] {
		first.owner = pthread_self();
		thread->doWork();
		originReturned.release();
	});
	std::thread destination([&] {
		wakeDestination.wait();
		second.owner = pthread_self();
		onDestination = true;
		thread->doWork();
	});
	origin.join();
	destination.join();
	check(first.unlocks == 1 && second.unlocks == 1,
		"waking a new host preserves its subsequent suspension lock");
	thread->onExit = nullptr;
	thread->doWork();
	std::puts("PASS suspension lock survives host handoff");
}

int main() {
	for (auto mode : {Mode::Call, Mode::Continuation, Mode::Syscall, Mode::Replacement,
		Mode::Unlock, Mode::Interrupt, Mode::InterruptedContinuation})
		run(mode);
	runLockHandoff();
	return 0;
}
