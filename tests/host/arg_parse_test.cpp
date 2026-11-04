// Runs the real parseNumericArgument() and dropTookEffect() of src/darlingserver.cpp, cut out by
// tests/host/extract-static.sh into the file named by ARG_PARSE_INC.
#include <cerrno>
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

// parseNumericArgument() exits on bad input, so each call runs in a child.
// Returns the parsed value, or -1 when the child exited with status 1.
static long parseInChild(const char* str, unsigned long max) {
	fflush(stdout);
	int fds[2];
	if (pipe(fds) != 0)
		abort();
	pid_t pid = fork();
	if (pid == 0) {
		close(fds[0]);
		freopen("/dev/null", "w", stderr);
		unsigned long v = parseNumericArgument("test", str, max);
		write(fds[1], &v, sizeof(v));
		_exit(0);
	}
	close(fds[1]);
	unsigned long v = 0;
	ssize_t n = read(fds[0], &v, sizeof(v));
	close(fds[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	if (n == (ssize_t)sizeof(v) && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return (long)v;
	return (WIFEXITED(status) && WEXITSTATUS(status) == 1) ? -1 : -2;
}

static void accepts(const char* str, unsigned long max, long expected) {
	char msg[128];
	snprintf(msg, sizeof(msg), "accepts \"%s\" as %ld", str, expected);
	check(parseInChild(str, max) == expected, msg);
}

static void rejects(const char* str, unsigned long max) {
	char msg[128];
	snprintf(msg, sizeof(msg), "rejects \"%s\" (max %lu)", str, max);
	check(parseInChild(str, max) == -1, msg);
}

int main() {
	const unsigned long idMax = UINT_MAX - 1;

	accepts("1000", idMax, 1000);
	accepts("0", idMax, 0);
	accepts("4294967294", idMax, 4294967294L);
	accepts("7", INT_MAX, 7);
	accepts("2147483647", INT_MAX, 2147483647L);

	rejects("4294967295", idMax); // (uid_t)-1: setresuid() would leave the id unchanged
	rejects("-1", idMax);
	rejects("-1000", idMax);
	rejects("18446744073709551616", idMax); // overflows unsigned long
	rejects("99999999999999999999999", idMax);
	rejects("", idMax);
	rejects("abc", idMax);
	rejects("1000x", idMax);
	rejects("1000 ", idMax);
	rejects(" 1000", idMax);
	rejects("+1000", idMax);
	rejects("0x10", idMax);
	rejects("2147483648", INT_MAX);

	// the process's own ids are, by construction, a completed drop; any other id is not
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;
	check(getresuid(&ruid, &euid, &suid) == 0 && getresgid(&rgid, &egid, &sgid) == 0, "getres*id");
	if (ruid == euid && euid == suid && rgid == egid && egid == sgid) {
		check(dropTookEffect(ruid, rgid), "drop confirmed when the ids match");
	}
	check(!dropTookEffect(ruid + 1, rgid), "drop not confirmed for another uid");
	check(!dropTookEffect(ruid, rgid + 1), "drop not confirmed for another gid");
	check(!dropTookEffect((uid_t)-1, (gid_t)-1), "drop not confirmed for (uid_t)-1");

	printf("%d of %d checks passed\n", checks - failures, checks);
	return failures ? 1 : 0;
}
