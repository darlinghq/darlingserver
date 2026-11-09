// Runs the real closeInheritedFds() and sanitizeProcessState() of src/darlingserver.cpp, cut out by
// tests/host/extract-static.sh into the file named by PROCESS_STATE_INC, in a child process whose
// state is set up the way a user could hand it to the setuid launcher.
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

// defined next to the functions in darlingserver.cpp
static mode_t userUmask = 022;

#include PROCESS_STATE_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static bool isOpen(int fd) {
	return fcntl(fd, F_GETFD) >= 0;
}

int main(int argc, char** argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: %s <private directory>\n", argv[0]);
		return 2;
	}
	std::fflush(stdout);

	pid_t pid = fork();
	if (pid == 0) {
		int keep[2], extra[2];
		if (pipe(keep) != 0 || pipe(extra) != 0 || chdir(argv[1]) != 0) {
			_exit(2);
		}
		int file = open(".", O_RDONLY | O_DIRECTORY);
		int high = fcntl(file, F_DUPFD, 200);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		sigset_t blocked;
		sigemptyset(&blocked);
		sigaddset(&blocked, SIGUSR1);
		sigaddset(&blocked, SIGINT);
		sigprocmask(SIG_BLOCK, &blocked, NULL);
		umask(077);
		struct rlimit core;
		getrlimit(RLIMIT_CORE, &core);
		core.rlim_cur = core.rlim_max;
		setrlimit(RLIMIT_CORE, &core);
		// a closed standard input, which the next open() would otherwise get
		close(STDIN_FILENO);

		sanitizeProcessState(keep[1]);

		CHECK(isOpen(STDIN_FILENO) && isOpen(STDOUT_FILENO) && isOpen(STDERR_FILENO), "the standard descriptors are open");
		CHECK(isOpen(keep[1]), "the launcher's pipe is kept");
		CHECK(!isOpen(keep[0]) && !isOpen(extra[0]) && !isOpen(extra[1]) && !isOpen(file) && !isOpen(high), "every other inherited descriptor is closed");
		struct sigaction action;
		sigaction(SIGCHLD, NULL, &action);
		bool dfl = action.sa_handler == SIG_DFL;
		sigaction(SIGTERM, NULL, &action);
		CHECK(dfl && action.sa_handler == SIG_DFL, "ignored signals are reset to their default action");
		sigset_t mask;
		sigprocmask(SIG_SETMASK, NULL, &mask);
		CHECK(!sigismember(&mask, SIGUSR1) && !sigismember(&mask, SIGINT), "the signal mask is cleared");
		getrlimit(RLIMIT_CORE, &core);
		CHECK(core.rlim_cur == 0, "no core file can be written");
		CHECK(prctl(PR_GET_DUMPABLE) == 0, "the process is not dumpable");
		mode_t now = umask(0);
		CHECK(now == 022 && userUmask == 077, "the umask is 022 and the user's is kept");
		char cwd[PATH_MAX];
		CHECK(getcwd(cwd, sizeof(cwd)) && std::strcmp(cwd, "/") == 0, "the working directory is /");
		std::fflush(stdout);
		_exit(fails ? 1 : 0);
	}

	int status = 0;
	waitpid(pid, &status, 0);
	bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	std::printf("%s\n", ok ? "all passed" : "FAILED");
	return ok ? 0 : 1;
}
