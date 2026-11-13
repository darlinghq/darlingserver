// Copyright (C) 2026 Lubos Dolezel
// How darlingserver decides its mode (src/run-mode.cpp, compiled unchanged), run as an ordinary user.
// The mode of a real process is checked in a child that makes its own user namespace, as the launcher's
// rootless mode does. No root is needed.
#include <darlingserver/run-mode.hpp>
#include <darling-config.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace DarlingServer::RunMode;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static std::string libexecFor(Mode mode, const char* value, bool* ok = nullptr) {
	std::string path, error;
	bool good = resolveLibexecPath(mode, value, path, error);
	if (ok) {
		*ok = good;
	}
	return path;
}

static void testNamespaceMap() {
	CHECK(isInitialUserNamespace("         0          0 4294967295\n"), "the initial namespace's map is recognised");
	CHECK(isInitialUserNamespace("0 0 4294967295"), "without padding or a newline too");
	CHECK(!isInitialUserNamespace("         0       1000          1\n"), "a map of one id to the user is not the initial namespace");
	CHECK(!isInitialUserNamespace("         0     100000      65536\n"), "a subordinate id range is not the initial namespace");
	CHECK(!isInitialUserNamespace("0 0 1\n"), "a map of root to itself only is not the initial namespace");
	CHECK(!isInitialUserNamespace(""), "empty contents are not the initial namespace");
	CHECK(!isInitialUserNamespace("0 0 4294967295 extra\n"), "trailing fields are not accepted");
	CHECK(!isInitialUserNamespace("zero 0 4294967295\n"), "a non-number is not accepted");
}

static void testClassify() {
	CHECK(classify(true, true, false) == Mode::Root, "root ids in the initial namespace are Root");
	CHECK(classify(true, false, true) == Mode::Root, "capabilities in the initial namespace are Root");
	CHECK(classify(true, true, true) == Mode::Root, "both are Root");
	CHECK(classify(true, false, false) == Mode::NonRoot, "no root and no capabilities in the initial namespace is NonRoot");
	CHECK(classify(false, true, true) == Mode::Rootless, "root inside another user namespace is Rootless, not Root");
	CHECK(classify(false, false, false) == Mode::Rootless, "another user namespace is Rootless");
}

static void testLibexec() {
	bool ok;
	CHECK(libexecFor(Mode::Root, "/tmp/attacker", &ok) == LIBEXEC_PATH && ok, "Root ignores the override");
	CHECK(libexecFor(Mode::Root, "relative/..", &ok) == LIBEXEC_PATH && ok, "Root ignores even an invalid override");
	CHECK(libexecFor(Mode::NonRoot, nullptr, &ok) == LIBEXEC_PATH && ok, "NonRoot without an override uses the compiled-in path");
	CHECK(libexecFor(Mode::NonRoot, "", &ok) == LIBEXEC_PATH && ok, "an empty override is no override");
	CHECK(libexecFor(Mode::NonRoot, "/data/app/libexec/darling", &ok) == "/data/app/libexec/darling" && ok, "NonRoot takes an absolute override");
	CHECK(libexecFor(Mode::Rootless, "/opt/dar ling//", &ok) == "/opt/dar ling" && ok, "Rootless takes it too, without trailing slashes");
	libexecFor(Mode::NonRoot, "relative/path", &ok);
	CHECK(!ok, "a relative override is refused");
	libexecFor(Mode::NonRoot, "/opt/../etc", &ok);
	CHECK(!ok, "a .. component is refused");
	libexecFor(Mode::NonRoot, "/opt/./x", &ok);
	CHECK(!ok, "a . component is refused");
	libexecFor(Mode::NonRoot, "/opt/a\nb", &ok);
	CHECK(!ok, "a control character is refused");
	libexecFor(Mode::NonRoot, ("/" + std::string(5000, 'a')).c_str(), &ok);
	CHECK(!ok, "an overlong override is refused");
	CHECK(libexecFor(Mode::NonRoot, "/opt/..x/.y", &ok) == "/opt/..x/.y" && ok, "names that only start with dots are fine");
}

static void testDetect() {
	// as an ordinary user without capabilities
	if (geteuid() != 0) {
		CHECK(detect() == Mode::NonRoot, "an ordinary process is NonRoot");
	}

	pid_t pid = fork();
	if (pid == 0) {
		uid_t uid = getuid();
		gid_t gid = getgid();
		if (unshare(CLONE_NEWUSER) != 0) {
			_exit(77);
		}
		char map[64];
		int fd = open("/proc/self/setgroups", O_WRONLY);
		if (fd >= 0) { write(fd, "deny", 4); close(fd); }
		snprintf(map, sizeof(map), "0 %u 1", uid);
		fd = open("/proc/self/uid_map", O_WRONLY);
		if (fd < 0 || write(fd, map, strlen(map)) < 0) { _exit(78); }
		close(fd);
		snprintf(map, sizeof(map), "0 %u 1", gid);
		fd = open("/proc/self/gid_map", O_WRONLY);
		if (fd < 0 || write(fd, map, strlen(map)) < 0) { _exit(78); }
		close(fd);
		// inside, the process is uid 0 with every capability, yet it is not Root
		_exit(getuid() == 0 && detect() == Mode::Rootless ? 0 : 1);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
		std::printf("SKIP user namespaces are not available\n");
	} else {
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "uid 0 with capabilities inside a user namespace is Rootless");
	}
}

int main() {
	testNamespaceMap();
	testClassify();
	testLibexec();
	testDetect();
	std::printf("%s\n", fails ? "FAILED" : "all passed");
	return fails ? 1 : 0;
}
