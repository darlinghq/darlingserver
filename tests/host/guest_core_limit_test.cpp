// Copyright (C) 2026 Lubos Dolezel
//
// Runs guestCoreLimit() of src/darlingserver.cpp, cut out by tests/host/extract-static.sh into the
// file named by GUEST_CORE_LIMIT_INC: launchd, and every process of the container after it, starts with
// a core size limit of 0 under the server's hard limit, as processes on macOS start with none (XNU's
// DFLCSIZ). A program with a large, sparsely used address space that crashes under it is gone at once
// (with a piped core_pattern the kernel still starts a dump, but the handler is told the limit is 0 and
// takes nothing), and a process can still raise the limit back up to the hard limit without
// privileges, as `ulimit -c unlimited` does.
#include <csignal>
#include <cstdio>
#include <ctime>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include GUEST_CORE_LIMIT_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// Seconds until a child that applies `limit`, reserves 64 GiB of which it touches one page per GiB
// (as JavaScriptCore reserves its heaps) and then dies of SIGSEGV's default action is reaped, or -1
// when it did not die of SIGSEGV.
static double crashSeconds(const struct rlimit& limit) {
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	pid_t pid = fork();
	if (pid == 0) {
		if (setrlimit(RLIMIT_CORE, &limit) != 0)
			_exit(2);
		const size_t gib = size_t(1) << 30;
		char* region = static_cast<char*>(mmap(nullptr, 64 * gib, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
		if (region == MAP_FAILED)
			_exit(4);
		for (size_t i = 0; i < 64; i++)
			region[i * gib] = 1;
		// the default action, not a sanitizer's handler
		signal(SIGSEGV, SIG_DFL);
		raise(SIGSEGV);
		_exit(3);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	clock_gettime(CLOCK_MONOTONIC, &end);
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV)
		return -1;
	return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main() {
	struct rlimit server = { RLIM_INFINITY, RLIM_INFINITY };
	struct rlimit guest = guestCoreLimit(server);
	CHECK(guest.rlim_cur == 0, "no core file by default");
	CHECK(guest.rlim_max == RLIM_INFINITY, "the hard limit is the server's (unlimited)");

	struct rlimit capped = { 1 << 20, 1 << 20 };
	struct rlimit guestCapped = guestCoreLimit(capped);
	CHECK(guestCapped.rlim_cur == 0 && guestCapped.rlim_max == (rlim_t)(1 << 20), "the hard limit is the server's (capped)");

	struct rlimit current;
	getrlimit(RLIMIT_CORE, &current);
	struct rlimit applied = guestCoreLimit(current);
	double seconds = crashSeconds(applied);
	std::printf("crash of a 64 GiB sparse process took %.2f s\n", seconds);
	CHECK(seconds >= 0 && seconds < 5, "a crash under the guest limit is over at once");

	pid_t pid = fork();
	if (pid == 0) {
		if (setrlimit(RLIMIT_CORE, &applied) != 0)
			_exit(1);
		struct rlimit raised = applied;
		raised.rlim_cur = raised.rlim_max;
		_exit(setrlimit(RLIMIT_CORE, &raised) == 0 ? 0 : 1);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "an unprivileged process raises it back to the hard limit");

	return fails ? 1 : 0;
}
