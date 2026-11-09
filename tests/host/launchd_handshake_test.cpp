// Copyright (C) 2026 Lubos Dolezel
//
// Runs sendReadyByte() and readReadyByte() of src/darlingserver.cpp, cut out by
// tests/host/extract-static.sh into the file named by LAUNCHD_HANDSHAKE_INC, over a socket pair
// shared with a child process, as the server and launchd's process use them: the reader learns
// whether the other side got ready or exited first, and a signal does not cut the wait short.
#include <cerrno>
#include <cstdio>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include LAUNCHD_HANDSHAKE_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static void onAlarm(int) {}

// the child gets fds[0], the parent keeps fds[1]; `child` runs in the child, which then exits
template <typename F>
static bool parentReads(F child) {
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
		return false;
	pid_t pid = fork();
	if (pid == 0) {
		close(fds[1]);
		child(fds[0]);
		_exit(0);
	}
	close(fds[0]);
	bool ready = readReadyByte(fds[1]);
	close(fds[1]);
	kill(pid, SIGKILL);
	waitpid(pid, nullptr, 0);
	return ready;
}

int main() {
	CHECK(parentReads([](int fd) { sendReadyByte(fd); }), "the other side reports that it is ready");
	CHECK(!parentReads([](int) {}), "the other side exits without reporting: not ready");
	CHECK(!parentReads([](int fd) { close(fd); pause(); }), "the other side closes its end: not ready");

	// a signal arriving during the wait (no SA_RESTART) must not be taken for a failure
	struct sigaction sa = {};
	sa.sa_handler = onAlarm;
	sigaction(SIGALRM, &sa, nullptr);
	pid_t parent = getpid();
	CHECK(parentReads([parent](int fd) {
		usleep(100000);
		kill(parent, SIGALRM);
		usleep(100000);
		sendReadyByte(fd);
	}), "an interrupted wait is resumed");

	// the green light in the other direction: the child gets it, or end-of-file when the server is gone
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
	CHECK(sendReadyByte(fds[1]) && readReadyByte(fds[0]), "a byte sent on one end is read on the other");
	close(fds[1]);
	CHECK(!readReadyByte(fds[0]), "end-of-file once the other end is closed");
	close(fds[0]);

	if (fails) {
		std::printf("%d check(s) failed\n", fails);
		return 1;
	}
	std::printf("all checks passed\n");
	return 0;
}
