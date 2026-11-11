// Copyright (C) 2026 Lubos Dolezel
//
// Runs findThreadByStackHint() of src/thread.cpp, cut out by tests/host/extract-static.sh into the
// file named by THREAD_DISCOVERY_INC, against the real threads of a child process. ptrace and
// waitpid go to the kernel; the test can make a register read fail, interrupt a wait with EINTR, or
// make a thread look as if it exited before it stopped. Every thread must be detached afterwards.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <string>
#include <system_error>
#include <vector>
#include <elf.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// what the wrappers below do to the function under test
static std::set<pid_t> unreadable;  // register reads of these threads fail with EIO
static pid_t vanishing = -1;        // this thread looks as if it exited before stopping
static int interruptWaits;          // this many waits fail with EINTR first

static bool isRegisterRead(int request) {
#if defined(__x86_64__)
	return request == PTRACE_GETREGS;
#else
	return request == PTRACE_GETREGSET;
#endif
}

static long testPtrace(int request, pid_t pid, void* addr, void* data) {
	if (isRegisterRead(request) && unreadable.count(pid)) {
		errno = EIO;
		return -1;
	}
	return ptrace(static_cast<__ptrace_request>(request), pid, addr, data);
}

static pid_t testWaitpid(pid_t pid, int* status, int options) {
	if (interruptWaits > 0) {
		--interruptWaits;
		errno = EINTR;
		return -1;
	}
	pid_t ret = waitpid(pid, status, options);
	if (ret == pid && pid == vanishing) {
		// stand-in for a thread that exited: it is no longer traced, and the status says so
		ptrace(PTRACE_DETACH, pid, 0, 0);
		*status = 0; // exited with status 0
	}
	return ret;
}

#define ptrace testPtrace
#define waitpid testWaitpid
#include THREAD_DISCOVERY_INC
#undef ptrace
#undef waitpid

// the child: three threads report their ID and an address in their stack, then block
static const int threadCount = 3;
struct ThreadInfo {
	pid_t tid;
	uintptr_t stackAddress;
};
static int reportFd;

static void* childThread(void*) {
	// the frame address, not a local's: under ASan locals can live in a heap-allocated fake stack
	ThreadInfo info = { static_cast<pid_t>(syscall(SYS_gettid)), reinterpret_cast<uintptr_t>(__builtin_frame_address(0)) };
	if (write(reportFd, &info, sizeof(info)) != sizeof(info))
		_exit(1);
	for (;;)
		pause();
	return nullptr;
}

static bool traced(pid_t child, pid_t tid) {
	std::ifstream status("/proc/" + std::to_string(child) + "/task/" + std::to_string(tid) + "/status");
	std::string line;
	while (std::getline(status, line)) {
		if (line.rfind("TracerPid:", 0) == 0)
			return std::stol(line.substr(10)) != 0;
	}
	return false;
}

static bool noneTraced(pid_t child, const std::vector<ThreadInfo>& threads) {
	for (const auto& t : threads)
		if (traced(child, t.tid))
			return false;
	return true;
}

// runs the function and turns an exception into a distinct result
static const pid_t threw = -2;
static pid_t run(const std::vector<pid_t>& ids, uintptr_t hint, bool& guessed) {
	try {
		return findThreadByStackHint(ids, reinterpret_cast<void*>(hint), guessed);
	} catch (const std::system_error& e) {
		std::printf("     (threw: %s)\n", e.what());
		guessed = false;
		return threw;
	}
}

int main() {
	int fds[2];
	if (pipe(fds) != 0) {
		std::perror("pipe");
		return 1;
	}

	pid_t child = fork();
	if (child == 0) {
		close(fds[0]);
		reportFd = fds[1];
		for (int i = 0; i < threadCount; i++) {
			pthread_t t;
			if (pthread_create(&t, nullptr, childThread, nullptr) != 0)
				_exit(1);
		}
		for (;;)
			pause();
	}
	close(fds[1]);

	std::vector<ThreadInfo> threads;
	for (int i = 0; i < threadCount; i++) {
		ThreadInfo info;
		if (read(fds[0], &info, sizeof(info)) != sizeof(info)) {
			std::printf("FAIL the child reports its threads\n");
			kill(child, SIGKILL);
			return 1;
		}
		threads.push_back(info);
	}
	close(fds[0]);

	// lowest and highest stack: nothing else can match a hint in the lowest one, while a hint in
	// the highest one has every other thread below it and must pick the nearest
	ThreadInfo lowest = threads[0], highest = threads[0];
	for (const auto& t : threads) {
		if (t.stackAddress < lowest.stackAddress)
			lowest = t;
		if (t.stackAddress > highest.stackAddress)
			highest = t;
	}
	std::vector<pid_t> ids;
	for (const auto& t : threads)
		ids.push_back(t.tid);

	if (ptrace(PTRACE_ATTACH, lowest.tid, 0, 0) == -1) {
		std::printf("SKIP cannot trace the child (%s); check kernel.yama.ptrace_scope\n", strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, nullptr, 0);
		return 0;
	}
	int status;
	waitpid(lowest.tid, &status, 0);
	ptrace(PTRACE_DETACH, lowest.tid, 0, 0);

	bool guessed;
	pid_t found;

	found = run(ids, highest.stackAddress, guessed);
	CHECK(found == highest.tid && !guessed, "the thread whose stack pointer is nearest below the hint is chosen");
	CHECK(noneTraced(child, threads), "every thread is detached");

	found = run(ids, lowest.stackAddress, guessed);
	CHECK(found == lowest.tid && !guessed, "a hint in the lowest stack matches only that thread");

	interruptWaits = 1;
	found = run(ids, highest.stackAddress, guessed);
	CHECK(found == highest.tid && interruptWaits == 0, "a wait interrupted by a signal is retried");
	CHECK(noneTraced(child, threads), "every thread is detached after an interrupted wait");

	unreadable = { lowest.tid };
	found = run(ids, lowest.stackAddress, guessed);
	CHECK(found == lowest.tid && guessed, "the only thread with unreadable registers is used when nothing else matches");
	CHECK(noneTraced(child, threads), "a thread with unreadable registers is detached");

	found = run(ids, highest.stackAddress, guessed);
	CHECK(found == highest.tid && !guessed, "a readable match wins over an unreadable thread");

	for (const auto& t : threads)
		if (t.tid != lowest.tid) {
			unreadable.insert(t.tid);
			break;
		}
	found = run(ids, lowest.stackAddress, guessed);
	CHECK(found == -1 && !guessed, "with two unreadable threads and no match, no thread is chosen");
	CHECK(noneTraced(child, threads), "every thread is detached with two unreadable threads");
	unreadable.clear();

	vanishing = lowest.tid;
	found = run(ids, highest.stackAddress, guessed);
	CHECK(found == highest.tid, "a thread that exits before it stops is skipped");
	vanishing = -1;
	CHECK(noneTraced(child, threads), "every thread is detached when one exits");

	kill(child, SIGKILL);
	waitpid(child, nullptr, 0);

	if (fails) {
		std::printf("%d check(s) failed\n", fails);
		return 1;
	}
	std::printf("all checks passed\n");
	return 0;
}
