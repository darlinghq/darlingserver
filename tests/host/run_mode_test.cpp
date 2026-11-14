// Copyright (C) 2026 Lubos Dolezel
// How darlingserver decides its mode (src/run-mode.cpp, compiled unchanged), run as an ordinary user.
// The mode of real processes is checked in children that make their own user namespaces: as the
// launcher's rootless mode does, and as a launcher started inside such a namespace would see it. No root
// is needed for those; run as root, it also checks a container-like namespace that maps many ids.
#include <darlingserver/run-mode.hpp>
#include <darling-config.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <sys/prctl.h>
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

static void testSingleIdMap() {
	CHECK(isSingleIdMap("         0       1000          1\n", 1000), "the launcher's rootless map is recognised");
	CHECK(isSingleIdMap("0 1000 1", 1000), "without padding or a newline too");
	CHECK(!isSingleIdMap("         0       1000          1\n", 1001), "a map of another user is not the launcher's");
	CHECK(!isSingleIdMap("         0     100000      65536\n", 100000), "a container's subordinate range is not a single id");
	CHECK(!isSingleIdMap("         0       1000          1\n         1     100000      65536\n", 1000), "a second line is not accepted");
	CHECK(!isSingleIdMap("      1000       1000          1\n", 1000), "the user must be 0 inside");
	CHECK(!isSingleIdMap("         0          0 4294967295\n", 0), "the initial namespace's map is not a single id");
	CHECK(!isSingleIdMap("", 1000), "empty contents are not accepted");
	CHECK(!isSingleIdMap("0 1000 1 extra\n", 1000), "trailing fields are not accepted");
}

static Facts facts(bool initial, ParentNamespace parent, bool launcherUserOnly, bool rootId, bool capabilities) {
	Facts f{};
	f.initialNamespace = initial;
	f.parent = parent;
	f.launcherUserOnly = launcherUserOnly;
	f.rootId = rootId;
	f.capabilities = capabilities;
	return f;
}

static void testClassify() {
	using P = ParentNamespace;
	CHECK(classify(facts(true, P::Unknown, false, true, false)) == Mode::Root, "root ids in the initial namespace are Root");
	CHECK(classify(facts(true, P::Unknown, false, false, true)) == Mode::Root, "capabilities in the initial namespace are Root");
	CHECK(classify(facts(true, P::Unknown, false, true, true)) == Mode::Root, "both are Root");
	CHECK(classify(facts(true, P::Unknown, false, false, false)) == Mode::NonRoot, "no root and no capabilities in the initial namespace is NonRoot");

	// a container (LXD, nspawn -U, rootless Podman): root of a namespace that maps many ids
	CHECK(classify(facts(false, P::Same, false, true, true)) == Mode::Root, "root in the launcher's own (container) namespace is Root");
	CHECK(classify(facts(false, P::Other, false, true, true)) == Mode::Root, "root in a namespace that maps more than the user is Root");
	CHECK(classify(facts(false, P::Unknown, false, true, true)) == Mode::Root, "root where the parent cannot be told is Root");
	CHECK(classify(facts(false, P::Same, false, false, false)) == Mode::NonRoot, "an ordinary user in the launcher's (container) namespace is NonRoot");

	// what the launcher's rootless mode makes
	CHECK(classify(facts(false, P::Other, true, true, true)) == Mode::Rootless, "root of a namespace mapping only the launcher's user is Rootless");
	CHECK(classify(facts(false, P::Same, true, true, true)) == Mode::Root, "the same, in the launcher's own namespace, is Root");
	CHECK(classify(facts(false, P::Unknown, true, true, true)) == Mode::Root, "the same, with the parent unknown, is Root");
	CHECK(classify(facts(false, P::Other, true, false, false)) == Mode::Rootless, "an unprivileged id in such a namespace is Rootless too");
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

static bool writeMap(const char* path, unsigned id) {
	char map[64];
	snprintf(map, sizeof(map), "0 %u 1", id);
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		return false;
	}
	bool ok = write(fd, map, strlen(map)) == (ssize_t) strlen(map);
	close(fd);
	return ok;
}

// Makes a user namespace mapping only this process's ids, as 0, the way the launcher's rootless child
// does. Returns false if user namespaces are not available, or are but cannot be used: some hosts
// (Ubuntu's AppArmor restriction of unprivileged user namespaces) let an unprivileged process create
// one without any capability in it, so it cannot write its own id maps.
static bool enterSingleIdNamespace(uid_t uid, gid_t gid) {
	if (unshare(CLONE_NEWUSER) != 0) {
		return false;
	}
	int fd = open("/proc/self/setgroups", O_WRONLY);
	if (fd >= 0) { write(fd, "deny", 4); close(fd); }
	return writeMap("/proc/self/gid_map", gid) && writeMap("/proc/self/uid_map", uid);
}

// Runs body in a child and returns its exit status: 0 for a pass, 77 when it cannot run here.
template<typename F>
static int inChild(F body) {
	pid_t pid = fork();
	if (pid == 0) {
		_exit(body());
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static void report(int status, const char* what) {
	if (status == 77) {
		std::printf("SKIP %s (user namespaces are not available or not usable)\n", what);
	} else {
		CHECK(status == 0, what);
	}
}

// As root, drops to an ordinary user first: the launcher's rootless mode only runs unprivileged.
static void becomeOrdinaryUser(uid_t& uid, gid_t& gid) {
	uid = getuid();
	gid = getgid();
	if (geteuid() == 0) {
		uid = gid = 65534;
		if (setgroups(0, nullptr) != 0 || setresgid(gid, gid, gid) != 0 || setresuid(uid, uid, uid) != 0) {
			_exit(79);
		}
		// changing ids made the process non-dumpable, which leaves its /proc files to root
		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	}
}

static void testDetect() {
	// as an ordinary user without capabilities
	if (geteuid() != 0) {
		CHECK(detect(getuid(), getgid()) == Mode::NonRoot, "an ordinary process is NonRoot");
	}

	// the launcher's rootless child: its parent stays in the namespace above
	report(inChild([] {
		uid_t uid; gid_t gid;
		becomeOrdinaryUser(uid, gid);
		if (!enterSingleIdNamespace(uid, gid)) {
			return 77;
		}
		// inside, the process is uid 0 with every capability, yet it is not Root
		return getuid() == 0 && detect(uid, gid) == Mode::Rootless ? 0 : 1;
	}), "uid 0 with capabilities in a namespace of the user's own, made below the launcher, is Rootless");

	report(inChild([] {
		uid_t uid; gid_t gid;
		becomeOrdinaryUser(uid, gid);
		if (!enterSingleIdNamespace(uid, gid)) {
			return 77;
		}
		return detect(uid + 1, gid) == Mode::Root && detect(uid, gid + 1) == Mode::Root ? 0 : 1;
	}), "the same namespace with another user or group given is Root");

	// A launcher inside such a namespace (`unshare -Ur`, a single-id container) shares it with
	// darlingserver: root there is Root, as in a container.
	report(inChild([] {
		uid_t uid; gid_t gid;
		becomeOrdinaryUser(uid, gid);
		if (!enterSingleIdNamespace(uid, gid)) {
			return 77;
		}
		return inChild([] { return detect(0, 0) == Mode::Root ? 0 : 1; });
	}), "uid 0 in the launcher's own namespace is Root");

	// A container whose root runs the launcher: a namespace that maps a range of ids. Only root can
	// write such a map (without newuidmap).
	if (geteuid() != 0) {
		std::printf("SKIP a namespace mapping many ids (needs root to write the map)\n");
		return;
	}
	for (bool sameAsParent: { false, true }) {
		int ready[2], go[2];
		if (pipe(ready) != 0 || pipe(go) != 0) {
			CHECK(false, "pipes");
			return;
		}
		pid_t pid = fork();
		if (pid == 0) {
			char c = 0;
			close(ready[0]);
			close(go[1]);
			if (unshare(CLONE_NEWUSER) != 0) {
				_exit(77);
			}
			write(ready[1], &c, 1);
			if (read(go[0], &c, 1) != 1 || c != 1) {
				_exit(78);
			}
			// root of the container: uid 0 inside, every capability
			if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
				_exit(80);
			}
			if (sameAsParent) {
				// the launcher and darlingserver both in the container's namespace
				_exit(inChild([] { return detect(1000, 1000) == Mode::Root ? 0 : 1; }));
			}
			// darlingserver in a container's namespace below the launcher's, even with a user given
			// that the range includes
			_exit(detect(0, 0) == Mode::Root && detect(1000, 1000) == Mode::Root ? 0 : 1);
		}
		close(ready[1]);
		close(go[0]);
		char c = 0;
		bool mapped = false;
		if (read(ready[0], &c, 1) == 1) {
			char path[64];
			snprintf(path, sizeof(path), "/proc/%d/uid_map", (int) pid);
			int fd = open(path, O_WRONLY);
			mapped = fd >= 0 && write(fd, "0 100000 65536", 14) == 14;
			if (fd >= 0) close(fd);
			snprintf(path, sizeof(path), "/proc/%d/gid_map", (int) pid);
			fd = open(path, O_WRONLY);
			mapped = mapped && fd >= 0 && write(fd, "0 100000 65536", 14) == 14;
			if (fd >= 0) close(fd);
		}
		c = mapped ? 1 : 0;
		write(go[1], &c, 1);
		close(ready[0]);
		close(go[1]);
		int status = 0;
		waitpid(pid, &status, 0);
		report(WIFEXITED(status) ? WEXITSTATUS(status) : 1, sameAsParent
			? "root of a container namespace mapping many ids, with the launcher in it too, is Root"
			: "root of a namespace mapping many ids below the launcher's is Root");
	}
}

int main() {
	testNamespaceMap();
	testSingleIdMap();
	testClassify();
	testLibexec();
	testDetect();
	std::printf("%s\n", fails ? "FAILED" : "all passed");
	return fails ? 1 : 0;
}
