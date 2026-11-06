// Runs the real parseNumericArgument() and dropTookEffect() of src/darlingserver.cpp, cut out by
// tests/host/extract-static.sh into the file named by ARG_PARSE_INC.
#include <cerrno>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

#include ARG_PARSE_INC

static int failures = 0;
static int checks = 0;

static void check(bool ok, const char* what) {
	checks++;
	if (!ok) {
		failures++;
		printf("FAIL: %s\n", what);
	}
}

// The parsers exit on bad input, so each call runs in a child.
// Returns the parsed value, or REJECTED when the child exited with status 1.
static const long long REJECTED = -1000000000000LL;

static long long parseInChild(bool isId, const char* str, long long max) {
	fflush(stdout);
	int fds[2];
	if (pipe(fds) != 0)
		abort();
	pid_t pid = fork();
	if (pid == 0) {
		close(fds[0]);
		freopen("/dev/null", "w", stderr);
		long long v = isId ? (long long)parseIdArgument("test", str) : parseNumericArgument("test", str, 0, max);
		write(fds[1], &v, sizeof(v));
		_exit(0);
	}
	close(fds[1]);
	long long v = 0;
	ssize_t n = read(fds[0], &v, sizeof(v));
	close(fds[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	if (n == (ssize_t)sizeof(v) && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return v;
	return (WIFEXITED(status) && WEXITSTATUS(status) == 1) ? REJECTED : REJECTED - 1;
}

static void idIs(const char* str, long long expected) {
	char msg[128];
	snprintf(msg, sizeof(msg), "id \"%s\" accepted as %lld", str, expected);
	check(parseInChild(true, str, 0) == expected, msg);
}

static void idRejected(const char* str) {
	char msg[128];
	snprintf(msg, sizeof(msg), "id \"%s\" rejected", str);
	check(parseInChild(true, str, 0) == REJECTED, msg);
}

static void fdIs(const char* str, long long expected) {
	char msg[128];
	snprintf(msg, sizeof(msg), "pipe fd \"%s\" accepted as %lld", str, expected);
	check(parseInChild(false, str, INT_MAX) == expected, msg);
}

static void fdRejected(const char* str) {
	char msg[128];
	snprintf(msg, sizeof(msg), "pipe fd \"%s\" rejected", str);
	check(parseInChild(false, str, INT_MAX) == REJECTED, msg);
}

int main() {
	idIs("1000", 1000);
	idIs("0", 0);
	idIs("4294967294", 4294967294LL);
	// the launcher formats ids with %d, so 3000000000 arrives as -1294967296
	idIs("-1294967296", 3000000000LL);
	idIs("3000000000", 3000000000LL);
	idIs("-2147483648", 2147483648LL);
	idIs("2147483647", 2147483647LL);
	idIs("-2", 4294967294LL);

	idRejected("4294967295"); // (uid_t)-1: setresuid() would leave the id unchanged
	idRejected("-1");
	idRejected("-2147483649"); // below INT_MIN
	idRejected("4294967296");
	idRejected("18446744073709551616");
	idRejected("99999999999999999999999");
	idRejected("");
	idRejected("-");
	idRejected("--1");
	idRejected("abc");
	idRejected("1000x");
	idRejected("1000 ");
	idRejected(" 1000");
	idRejected("+1000");
	idRejected("0x10");

	fdIs("7", 7);
	fdIs("2147483647", 2147483647LL);
	fdRejected("2147483648");
	fdRejected("-1");
	fdRejected("-7");
	fdRejected("");
	fdRejected("7x");

	// dropIdsMatch(): every one of the six ids must equal the target
	const uid_t u = 1000;
	const gid_t g = 1001;
	check(dropIdsMatch(u, g, u, u, u, g, g, g), "all six ids match");
	check(!dropIdsMatch(u, g, 0, u, u, g, g, g), "ruid left at 0");
	check(!dropIdsMatch(u, g, u, 0, u, g, g, g), "euid left at 0");
	check(!dropIdsMatch(u, g, u, u, 0, g, g, g), "suid left at 0");
	check(!dropIdsMatch(u, g, u, u, u, 0, g, g), "rgid left at 0");
	check(!dropIdsMatch(u, g, u, u, u, g, 0, g), "egid left at 0");
	check(!dropIdsMatch(u, g, u, u, u, g, g, 0), "sgid left at 0");

	// dropTookEffect() reads the process's own ids: a completed drop for the current ids, not for others
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;
	check(getresuid(&ruid, &euid, &suid) == 0 && getresgid(&rgid, &egid, &sgid) == 0, "getres*id");
	if (ruid == euid && euid == suid && rgid == egid && egid == sgid) {
		check(dropTookEffect(ruid, rgid), "drop confirmed when the ids match");
	}
	check(!dropTookEffect(ruid + 1, rgid), "drop not confirmed for another uid");
	check(!dropTookEffect(ruid, rgid + 1), "drop not confirmed for another gid");

	printf("%d of %d checks passed\n", checks - failures, checks);
	return failures ? 1 : 0;
}
