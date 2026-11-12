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

#define _GNU_SOURCE 1
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <iostream>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <filesystem>
#include <climits>
#include <string>
#include <sys/wait.h>
#include <sysexits.h>
#include <grp.h>
#include <vector>

#include <darling-config.h>

#include <darlingserver/server.hpp>
#include <darlingserver/config.hpp>
#include <darlingserver/prefix-setup.hpp>

#ifndef DARLINGSERVER_INIT_PROCESS
	#define DARLINGSERVER_INIT_PROCESS "/sbin/launchd"
#endif

#if DSERVER_ASAN
	#include <sanitizer/lsan_interface.h>
#endif

// TODO: most of the code here was ported over from startup/darling.c; we should C++-ify it.

// The user's directory of this kind (an xdg-user-dirs name such as "DOWNLOAD"), exactly as
// xdg-user-dir prints it, including its fallback to $HOME (or $HOME/Desktop) when the file or the
// entry is missing. The configuration file is read and parsed here rather than by running
// xdg-user-dir, a shell script that sources it: this runs with the user's ids only, and nothing the
// user configures gets to run. An empty result (xdg-user-dir printing an empty line) means no link.
static bool xdgDirectory(const std::string& config, const char* name, const char* home, std::string& dir)
{
	dir = DarlingServer::PrefixSetup::userDirOrDefault(config, name, home);
	return !dir.empty();
}

// Reads the user's user-dirs.dirs, from $XDG_CONFIG_HOME or else ~/.config. Without one, contents
// stays empty and every directory gets xdg-user-dir's fallback.
static bool readUserDirsConfig(const char* home, std::string& contents)
{
	const char* configHome = getenv("XDG_CONFIG_HOME");
	std::string path = (configHome && configHome[0] == '/') ? std::string(configHome) : std::string(home) + "/.config";
	path += "/user-dirs.dirs";

	int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return false;

	struct stat st;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
	{
		close(fd);
		return false;
	}

	char buffer[4096];
	ssize_t got;
	while (contents.size() < 65536 && (got = read(fd, buffer, sizeof(buffer))) > 0)
		contents.append(buffer, got);
	close(fd);
	return true;
}

void setupUserHome(const char* prefix, uid_t originalUID)
{
	char buf[4096], buf2[4096];

	snprintf(buf, sizeof(buf), "%s/Users", prefix);

	// Remove the old /Users symlink that may exist
	unlink(buf);

	// mkdir /Users
	mkdir(buf, 0777);

	// mkdir /Users/Shared
	strcat(buf, "/Shared");
	mkdir(buf, 0777);

	const char* home = getenv("HOME");

	const char* login = NULL;
	struct passwd* pw = getpwuid(originalUID);

	if (pw != NULL)
		login = pw->pw_name;

	if (!login)
		login = getlogin();

	if (!login)
	{
		fprintf(stderr, "Cannot determine your user name\n");
		exit(1);
	}
	if (!home)
	{
		fprintf(stderr, "Cannot determine your home directory\n");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "%s/Users/%s", prefix, login);

	// mkdir /Users/$LOGIN
	mkdir(buf, 0755);

	snprintf(buf2, sizeof(buf2), "/Volumes/SystemRoot%s", home);

	strcat(buf, "/LinuxHome");
	unlink(buf);

	// symlink /Users/$LOGIN/LinuxHome -> $HOME
	symlink(buf2, buf);

	std::string userDirsConfig;
	readUserDirsConfig(home, userDirsConfig);

	static const char* xdgmap[][2] = {
		{ "DESKTOP", "Desktop" },
		{ "DOWNLOAD", "Downloads" },
		{ "PUBLICSHARE", "Public" },
		{ "DOCUMENTS", "Documents" },
		{ "MUSIC", "Music" },
		{ "PICTURES", "Pictures" },
		{ "VIDEOS", "Movies" },
	};

	for (int i = 0; i < sizeof(xdgmap) / sizeof(xdgmap[0]); i++)
	{
		std::string dir;
		if (!xdgDirectory(userDirsConfig, xdgmap[i][0], home, dir))
			continue;

		snprintf(buf2, sizeof(buf2), "/Volumes/SystemRoot%s", dir.c_str());
		snprintf(buf, sizeof(buf), "%s/Users/%s/%s", prefix, login, xdgmap[i][1]);

		unlink(buf);
		symlink(buf2, buf);
	}
}

void setupCoredumpPattern(void)
{
	FILE* f = fopen("/proc/sys/kernel/core_pattern", "w");
	if (f != NULL)
	{
		// This is how macOS saves core dumps
		fputs("/cores/core.%p\n", f);
		fclose(f);
	}
}

static void wipeDir(const char* dirpath)
{
	char path[4096];
	struct dirent* ent;
	DIR* dir = opendir(dirpath);

	if (!dir)
		return;

	while ((ent = readdir(dir)) != NULL)
	{
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);

		if (ent->d_type == DT_DIR)
		{
			wipeDir(path);
			rmdir(path);
		}
		else
			unlink(path);
	}

	closedir(dir);
}

static void darlingPreInit(const char* prefix)
{
	// TODO: Run /usr/libexec/makewhatis
	// Clear runtime state, not /var/tmp files that applications may need
	// across separate server invocations using the same prefix.
	const char* dirs[] = {
		"/var/run"
	};

	char fullpath[4096];
	strcpy(fullpath, prefix);
	const size_t prefixLen = strlen(fullpath);

	for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++)
	{
		fullpath[prefixLen] = 0;
		strcat(fullpath, dirs[i]);
		wipeDir(fullpath);
	}
}

static void detachStdio(void)
{
	int fd = open("/dev/null", O_RDWR);

	if (fd < 0)
		return;

	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);

	if (fd > STDERR_FILENO)
		close(fd);
}

void spawnLaunchd(const char* prefix)
{
	puts("Bootstrapping the container with launchd...");

	// putenv("KQUEUE_DEBUG=1");

	auto tmp = (std::string(prefix) + "/.darlingserver.sock");

	const char* initPath = getenv("DSERVER_INIT");

	if (!initPath) {
		initPath = DARLINGSERVER_INIT_PROCESS;
	}

	setenv("__mldr_DYLD_ROOT_PATH", LIBEXEC_PATH, 1);
	setenv("__mldr_sockpath", tmp.c_str(), 1);

	// These describe the host user and its host paths. launchd sets them for
	// each job from the job's own account, but never replaces inherited ones.
	static const char* const hostIdentityVars[] = { "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR" };
	for (const char* var: hostIdentityVars) {
		unsetenv(var);
	}

	detachStdio();
	execl(DarlingServer::Config::defaultMldrPath.data(), "mldr!" LIBEXEC_PATH "/usr/libexec/darling/vchroot", "vchroot", prefix, initPath, NULL);

	fprintf(stderr, "Failed to exec launchd: %s\n", strerror(errno));
	abort();
}

static bool testEnvVar(const char* var_name) {
	const char* var = getenv(var_name);

	if (!var) {
		return false;
	}

	auto len = strlen(var);

	if (len > 0 && (var[0] == '1' || var[0] == 't' || var[0] == 'T')) {
		return true;
	}

	return false;
};

static bool isOnWsl1() {
	static bool initialized = false;
	static bool result = false;
	if (!initialized) {
		initialized = true;
		// WSL1 kernels report a release such as "4.4.0-19041-Microsoft"; WSL2 uses "-microsoft-standard".
		// The match is case-sensitive on purpose: a case-insensitive one would also match WSL2,
		// which does not need the WSL1 workarounds.
		struct utsname name;
		result = uname(&name) == 0 && strstr(name.release, "Microsoft") != NULL;
	}

	return result;
}

static void temp_drop_privileges(uid_t uid, gid_t gid) {
	// it's important to drop GID first, because non-root users can't change their GID
	if (setresgid(gid, gid, 0) < 0) {
		fprintf(stderr, "Failed to temporarily drop group privileges\n");
		exit(1);
	}
	if (setresuid(uid, uid, 0) < 0) {
		fprintf(stderr, "Failed to temporarily drop user privileges\n");
		exit(1);
	}
};

// The launcher formats these with %d, so an id above INT_MAX arrives negative and must round-trip.
// Anything else is rejected rather than left at a default, because (uid_t)-1 makes
// setresuid()/setresgid() leave the id unchanged.
static long long parseNumericArgument(const char* what, const char* str, long long min, long long max) {
	char* end;
	errno = 0;
	bool negative = (str[0] == '-');
	const char* digits = negative ? str + 1 : str;
	if (digits[0] < '0' || digits[0] > '9') {
		fprintf(stderr, "darlingserver: invalid %s argument \"%s\"\n", what, str);
		exit(1);
	}
	long long value = strtoll(str, &end, 10);
	if (*end != '\0' || errno != 0 || value < min || value > max) {
		fprintf(stderr, "darlingserver: invalid %s argument \"%s\"\n", what, str);
		exit(1);
	}
	return value;
};

static uint32_t parseIdArgument(const char* what, const char* str) {
	uint32_t id = (uint32_t)parseNumericArgument(what, str, INT_MIN, UINT_MAX);
	if (id == UINT_MAX) {
		fprintf(stderr, "darlingserver: invalid %s argument \"%s\"\n", what, str);
		exit(1);
	}
	return id;
};

static bool dropIdsMatch(uid_t uid, gid_t gid, uid_t ruid, uid_t euid, uid_t suid, gid_t rgid, gid_t egid, gid_t sgid) {
	return ruid == uid && euid == uid && suid == uid && rgid == gid && egid == gid && sgid == gid;
};

static bool dropTookEffect(uid_t uid, gid_t gid) {
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;
	return getresuid(&ruid, &euid, &suid) == 0 && getresgid(&rgid, &egid, &sgid) == 0 &&
	       dropIdsMatch(uid, gid, ruid, euid, suid, rgid, egid, sgid);
};

// one byte over the socket pair between the server and launchd's process says "ready"
static bool sendReadyByte(int fd) {
	ssize_t ret;
	do {
		ret = write(fd, ".", 1);
	} while (ret < 0 && errno == EINTR);
	return ret == 1;
};

// false when the other side exited (or closed its end) without saying it is ready
static bool readReadyByte(int fd) {
	char byte;
	ssize_t ret;
	do {
		ret = read(fd, &byte, 1);
	} while (ret < 0 && errno == EINTR);
	return ret == 1;
};

static void perma_drop_privileges(uid_t uid, gid_t gid) {
	if (setresgid(gid, gid, gid) < 0) {
		fprintf(stderr, "Failed to drop group privileges\n");
		exit(1);
	}
	if (setresuid(uid, uid, uid) < 0) {
		fprintf(stderr, "Failed to drop user privileges\n");
		exit(1);
	}
	if (!dropTookEffect(uid, gid)) {
		fprintf(stderr, "Privilege drop did not take effect\n");
		exit(1);
	}
};

static void regain_privileges() {
	if (seteuid(0) < 0) {
		fprintf(stderr, "Failed to regain root EUID\n");
		exit(1);
	}
	if (setegid(0) < 0) {
		fprintf(stderr, "Failed to regain root EGID\n");
		exit(1);
	}

	if (setresuid(0, 0, 0) < 0) {
		fprintf(stderr, "Failed to regain root privileges\n");
		exit(1);
	}
	if (setresgid(0, 0, 0) < 0) {
		fprintf(stderr, "Failed to regain root privileges\n");
		exit(1);
	}
};

// Closes every descriptor from 3 up, except keep.
static void closeInheritedFds(int keep) {
#ifdef SYS_close_range
	bool closed = true;
	if (keep > 3) {
		closed = syscall(SYS_close_range, 3, keep - 1, 0) == 0;
	}
	if (closed && syscall(SYS_close_range, (keep >= 3) ? keep + 1 : 3, ~0U, 0) == 0) {
		return;
	}
#endif
	// kernels before 5.9
	std::vector<int> fds;
	DIR* dir = opendir("/proc/self/fd");
	if (!dir) {
		fprintf(stderr, "Cannot list the inherited file descriptors: %s\n", strerror(errno));
		exit(1);
	}
	while (struct dirent* ent = readdir(dir)) {
		char* end;
		long fd = strtol(ent->d_name, &end, 10);
		if (*end == '\0' && end != ent->d_name && fd > STDERR_FILENO && fd != keep && fd != dirfd(dir)) {
			fds.push_back(fd);
		}
	}
	closedir(dir);
	for (int fd: fds) {
		close(fd);
	}
};

// The umask the user started darling with; the user's own processes get it back.
static mode_t userUmask = 022;

// The launcher starts us as root, but with the process state the user started the launcher with.
// Reset what could make the root part of the start-up act differently or stop half-way, or leave a
// core file of a root process somewhere the user chose.
static void sanitizeProcessState(int pipefd) {
	// Missing standard descriptors would be taken by the files and directories opened as root below.
	for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
			int null = open("/dev/null", O_RDWR);
			if (null != fd) {
				exit(1);
			}
		}
	}

	// The pipe to the launcher is the only other descriptor meant for us.
	closeInheritedFds(pipefd);

	// Ignored and blocked signals survive exec. An ignored SIGCHLD would make the waits for our own
	// helper processes fail; others would change how a failure ends.
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig != SIGKILL && sig != SIGSTOP) {
			signal(sig, SIG_DFL);
		}
	}
	sigset_t none;
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);

	// No core file while we are root; the user's limit is restored (and raised) after the drop.
	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	struct rlimit core;
	if (getrlimit(RLIMIT_CORE, &core) == 0) {
		core.rlim_cur = 0;
		setrlimit(RLIMIT_CORE, &core);
	}

	// Files root makes get the modes it asks for, and no relative path means the user's directory.
	userUmask = umask(022);
	if (chdir("/") != 0) {
		fprintf(stderr, "Cannot change to /: %s\n", strerror(errno));
		exit(1);
	}
};

// The invoking user's supplementary groups, as the launcher passed them on.
static std::vector<gid_t> userGroups;

// Runs fn in a child process that has given up root for good, and waits for it. Work in the user's
// prefix that root is not needed for runs like this, so that nothing it does can get root back.
template<typename Fn>
static bool runAsUser(uid_t uid, gid_t gid, Fn&& fn) {
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Cannot fork: %s\n", strerror(errno));
		return false;
	} else if (pid == 0) {
		// the groups and gids first, while the uid can still change them
		if (setgroups(userGroups.size(), userGroups.data()) != 0 || setresgid(gid, gid, gid) != 0 ||
			setresuid(uid, uid, uid) != 0 || !dropTookEffect(uid, gid) || (uid != 0 && setresuid(-1, 0, -1) == 0))
		{
			fprintf(stderr, "Cannot switch to your user and group ids\n");
			_exit(1);
		}
		umask(userUmask);
		_exit(fn() ? 0 : 1);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) != pid) {
		if (errno != EINTR) {
			fprintf(stderr, "Cannot wait for a child process: %s\n", strerror(errno));
			return false;
		}
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
};

// Opens a path in or next to the user's prefix with the user's ids, so that it resolves exactly as
// it would for the user, and nowhere the user could not go.
static int openAsUser(int dirFd, const char* path, int flags, uid_t uid, gid_t gid) {
	temp_drop_privileges(uid, gid);
	int fd = openat(dirFd, path, flags | O_CLOEXEC);
	int error = errno;
	regain_privileges();
	errno = error;
	return fd;
};

static std::string procFdPath(int fd) {
	return "/proc/self/fd/" + std::to_string(fd);
};

// The prefix is a directory the user owns and can change at any time, also while root works in it.
// So it is opened once, as the user, and checked; everything root does inside it from then on is
// done relative to this descriptor, one name at a time and without following symbolic links, and the
// prefix is mounted on through the descriptor rather than its path.
struct PinnedPrefix {
	std::string parent; // the directory holding the prefix
	std::string name;   // the prefix's name in it
	int fd = -1;
};

static PinnedPrefix pinPrefix(const char* prefix, uid_t uid, gid_t gid) {
	PinnedPrefix pinned;

	// Paths built from the prefix go into fixed-size buffers; the launcher allows far less than this.
	if (strlen(prefix) > PATH_MAX / 2 || !DarlingServer::PrefixSetup::splitPath(prefix, pinned.parent, pinned.name)) {
		fprintf(stderr, "darlingserver: the prefix must be an absolute path other than / and shorter than %d bytes: %s\n", PATH_MAX / 2, prefix);
		exit(1);
	}

	// A symbolic link as the prefix's last component is resolved with the user's ids, and what it
	// leads to is checked like any other prefix.
	pinned.fd = openAsUser(AT_FDCWD, prefix, O_RDONLY | O_DIRECTORY, uid, gid);
	if (pinned.fd < 0) {
		fprintf(stderr, "Cannot open the prefix %s: %s\n", prefix, strerror(errno));
		exit(1);
	}

	struct stat st;
	if (fstat(pinned.fd, &st) != 0 || !DarlingServer::PrefixSetup::prefixDirAcceptable(st, uid, gid)) {
		fprintf(stderr, "The prefix %s must be a directory that you own and that nobody else can write to\n", prefix);
		exit(1);
	}

	return pinned;
};

// The overlay's work directory, in the "<prefix>.workdir" directory the launcher creates next to the
// prefix. overlayfs and fuse-overlayfs create, empty and rename entries in it as root, so they get a
// directory inside it that only root can use. Returns -1, after a message, if that is not possible.
static int openOverlayWorkDir(const PinnedPrefix& prefix, uid_t uid, gid_t gid) {
	static const char privateName[] = "private";
	std::string workName = prefix.name + ".workdir";
	struct stat st;

	int parentFd = openAsUser(AT_FDCWD, prefix.parent.c_str(), O_PATH | O_DIRECTORY, uid, gid);
	if (parentFd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", prefix.parent.c_str(), strerror(errno));
		return -1;
	}
	int workFd = openAsUser(parentFd, workName.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW, uid, gid);
	int error = errno;
	close(parentFd);
	if (workFd < 0) {
		fprintf(stderr, "Cannot open the work directory %s: %s\n", workName.c_str(), strerror(error));
		return -1;
	}
	if (fstat(workFd, &st) != 0 || !DarlingServer::PrefixSetup::workDirAcceptable(st, uid)) {
		fprintf(stderr, "The work directory %s must be a directory that you own and that nobody else can write to\n", workName.c_str());
		close(workFd);
		return -1;
	}

	if (mkdirat(workFd, privateName, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "Cannot create %s/%s: %s\n", workName.c_str(), privateName, strerror(errno));
		close(workFd);
		return -1;
	}
	int privateFd = openat(workFd, privateName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	error = errno;
	close(workFd);
	if (privateFd < 0 || fstat(privateFd, &st) != 0 || !DarlingServer::PrefixSetup::privateRootDirAcceptable(st)) {
		fprintf(stderr, "%s/%s must be a directory that only root can use: %s\n", workName.c_str(), privateName, privateFd < 0 ? strerror(error) : "it is not");
		if (privateFd >= 0) {
			close(privateFd);
		}
		return -1;
	}
	return privateFd;
};

// Root's own directory for assembling the prefix, on the new /dev/shm that only this mount namespace
// sees: nothing in a path below it can be renamed or replaced by the user.
static const char setupDir[] = "/dev/shm/.darlingserver-setup";

static bool makeSetupDir(const std::string& path) {
	if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "Cannot create %s: %s\n", path.c_str(), strerror(errno));
		return false;
	}
	struct stat st;
	if (lstat(path.c_str(), &st) != 0 || !DarlingServer::PrefixSetup::privateRootDirAcceptable(st)) {
		fprintf(stderr, "%s is not a directory that only root can use\n", path.c_str());
		return false;
	}
	return true;
};

static bool optionPathsArePlain(std::initializer_list<std::string> paths) {
	for (const auto& path: paths) {
		if (!DarlingServer::PrefixSetup::isPlainOptionPath(path)) {
			fprintf(stderr, "Cannot use an overlay: overlay mount options cannot carry the path %s, which has ',', ':', '\\' or control characters\n", path.c_str());
			return false;
		}
	}
	return true;
};

// Opens the assembled prefix where it was mounted in the setup directory, then moves that mount onto
// the prefix directory (named through its descriptor). Returns the descriptor of the assembled
// prefix's root, or -1 after a message.
static int moveOntoPrefix(const std::string& mountPoint, int prefixFd) {
	int mergedFd = open(mountPoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (mergedFd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", mountPoint.c_str(), strerror(errno));
		return -1;
	}
	if (mount(mountPoint.c_str(), procFdPath(prefixFd).c_str(), NULL, MS_MOVE, NULL) != 0) {
		fprintf(stderr, "Cannot move the assembled prefix into place: %s\n", strerror(errno));
		close(mergedFd);
		return -1;
	}
	return mergedFd;
};

// How the prefix is assembled on top of the read-only system image.
enum class FsMode {
	Overlayfs,
	FuseOverlayfs,
	Copy,
};

// The mode chosen for a prefix is recorded in this file at the root of the prefix by the darling client
// (the plain-text values are "overlayfs", "fuse-overlayfs" and "copy").
static const char fsModeFileName[] = ".darling-fsmode";

static bool readRecordedFsMode(const char* prefix, int prefixFd, uid_t uid, gid_t gid, FsMode& mode) {
	// The file is the user's: read it as the user, and only if it is a regular file.
	int fd = openAsUser(prefixFd, fsModeFileName, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, uid, gid);
	if (fd < 0) {
		return false;
	}
	struct stat st;
	FILE* file = (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) ? fdopen(fd, "r") : NULL;
	if (!file) {
		close(fd);
		return false;
	}

	char buffer[32] = {0};
	bool haveLine = fgets(buffer, sizeof(buffer), file) != NULL;
	fclose(file);
	if (!haveLine) {
		return false;
	}

	buffer[strcspn(buffer, "\r\n")] = '\0';

	if (strcmp(buffer, "overlayfs") == 0) {
		mode = FsMode::Overlayfs;
	} else if (strcmp(buffer, "fuse-overlayfs") == 0) {
		mode = FsMode::FuseOverlayfs;
	} else if (strcmp(buffer, "copy") == 0) {
		mode = FsMode::Copy;
	} else {
		fprintf(stderr, "Ignoring unknown filesystem mode \"%s\" recorded in %s/%s\n", buffer, prefix, fsModeFileName);
		return false;
	}
	return true;
};

static FsMode resolveFsMode(const char* prefix, int prefixFd, uid_t uid, gid_t gid) {
	// an explicit environment setting wins over everything else
	if (testEnvVar("DARLING_NOOVERLAYFS")) {
		return FsMode::Copy;
	} else if (getenv("DARLING_NOOVERLAYFS")) {
		return FsMode::Overlayfs;
	}

	FsMode recorded;
	if (readRecordedFsMode(prefix, prefixFd, uid, gid, recorded)) {
		return recorded;
	}

	// https://github.com/microsoft/WSL/issues/8748
	// Microsoft is being dumb with its overlayfs implementation and they don't seem to be willing to be fix WSL1-related bugs.
	// We therefore have to enable this hack on WSL1.
	if (isOnWsl1()) {
		return FsMode::Copy;
	}

	return FsMode::Overlayfs;
};

// Mounts the kernel's overlayfs with the prefix as its upper directory. The upper and work
// directories are named through their descriptors, so the option string holds no path the user chose.
static int mountOverlayfs(int prefixFd, int workFd) {
	std::string merged = std::string(setupDir) + "/merged";
	std::string upper = procFdPath(prefixFd);
	std::string work = procFdPath(workFd);
	if (!makeSetupDir(setupDir) || !makeSetupDir(merged) || !optionPathsArePlain({ LIBEXEC_PATH, upper, work })) {
		return -1;
	}

	std::string opts = "lowerdir=" LIBEXEC_PATH ",upperdir=" + upper + ",workdir=" + work;
	if (mount("overlay", merged.c_str(), "overlay", 0, (opts + ",index=off").c_str()) != 0 &&
		(errno != EINVAL || mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()) != 0))
	{
		fprintf(stderr, "Cannot mount overlay: %s\n", strerror(errno));
		return -1;
	}

	int mergedFd = moveOntoPrefix(merged, prefixFd);
	if (mergedFd >= 0) {
		rmdir(merged.c_str());
		rmdir(setupDir);
	}
	return mergedFd;
};

// Unlike the kernel's overlayfs, fuse-overlayfs does not place restrictions on the filesystem holding the upper layer.
// It takes paths, and resolves them again after starting, so it gets paths in root's setup directory,
// where the prefix and the work directory are bind-mounted (through their descriptors) for as long as
// the container runs.
static int mountFuseOverlayfs(int prefixFd, int workFd) {
	std::string upper = std::string(setupDir) + "/upper";
	std::string work = std::string(setupDir) + "/work";
	std::string merged = std::string(setupDir) + "/merged";
	if (!makeSetupDir(setupDir) || !makeSetupDir(upper) || !makeSetupDir(work) || !makeSetupDir(merged) ||
		!optionPathsArePlain({ LIBEXEC_PATH, upper, work }))
	{
		return -1;
	}
	if (mount(procFdPath(prefixFd).c_str(), upper.c_str(), NULL, MS_BIND, NULL) != 0 ||
		mount(procFdPath(workFd).c_str(), work.c_str(), NULL, MS_BIND, NULL) != 0)
	{
		fprintf(stderr, "Cannot bind-mount the prefix for fuse-overlayfs: %s\n", strerror(errno));
		return -1;
	}

	std::string opts = "lowerdir=" LIBEXEC_PATH ",upperdir=" + upper + ",workdir=" + work + ",allow_other";

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork to run fuse-overlayfs: %s\n", strerror(errno));
		return -1;
	} else if (pid == 0) {
		// It runs as root: only a PATH of root's directories, as the launcher gives us.
		static char* env[] = { (char*) "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
		environ = env;
		execlp("fuse-overlayfs", "fuse-overlayfs", "-o", opts.c_str(), merged.c_str(), NULL);
		fprintf(stderr, "Failed to run fuse-overlayfs: %s\n", strerror(errno));
		_exit(127);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "Failed to wait for fuse-overlayfs: %s\n", strerror(errno));
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "fuse-overlayfs failed\n");
		return -1;
	}

	return moveOntoPrefix(merged, prefixFd);
};

// Copies the system image into the prefix, as root so that the files keep their owners.
// Returns the prefix's descriptor again, or -1.
static int copyIntoPrefix(int prefixFd) {
	int lowerFd = open(LIBEXEC_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (lowerFd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", LIBEXEC_PATH, strerror(errno));
		return -1;
	}
	bool ok = DarlingServer::PrefixSetup::copyTree(lowerFd, prefixFd);
	close(lowerFd);
	if (!ok) {
		fprintf(stderr, "Cannot copy %s into the prefix\n", LIBEXEC_PATH);
		return -1;
	}
	return fcntl(prefixFd, F_DUPFD_CLOEXEC, 0);
};

// Gives the user their own copy of every directory of the system image, so that the directories of
// the assembled prefix are theirs. Done once, when the prefix is created.
static bool mirrorDirectoriesIntoPrefix(int prefixFd, uid_t uid, gid_t gid) {
	return runAsUser(uid, gid, [prefixFd]() {
		int lowerFd = open(LIBEXEC_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (lowerFd < 0) {
			fprintf(stderr, "Cannot open %s: %s\n", LIBEXEC_PATH, strerror(errno));
			return false;
		}
		DarlingServer::PrefixSetup::mirrorDirectories(lowerFd, prefixFd);
		close(lowerFd);
		return true;
	});
};

#if DSERVER_ASAN
static void handle_sigusr1(int signum) {
	__lsan_do_recoverable_leak_check();
};
#endif

int main(int argc, char** argv) {
	const char* prefix = NULL;
	uid_t originalUID = -1;
	gid_t originalGID = -1;
	int pipefd = -1;
	bool fix_permissions = false;
	pid_t launchdGlobalPID = -1;
	struct rlimit default_limit;
	struct rlimit increased_limit;
	FILE* nr_open_file = NULL;
	int childWaitFDs[2];
	struct rlimit core_limit;

	int mergedFd = -1;

	if (argc < 6) {
		fprintf(stderr, "darlingserver is not meant to be started manually\n");
		exit(1);
	}

#if DSERVER_EXTENDED_DEBUG
	if (getenv("DSERVER_WAIT4DEBUGGER")) {
		volatile bool debugged = false;
		while (!debugged);
	}
#endif

	prefix = argv[1];
	static_assert(sizeof(uid_t) == sizeof(unsigned int) && sizeof(gid_t) == sizeof(unsigned int));
	originalUID = parseIdArgument("uid", argv[2]);
	originalGID = parseIdArgument("gid", argv[3]);
	pipefd = parseNumericArgument("pipe fd", argv[4], 0, INT_MAX);

	if (argv[5][0] == '1') {
		fix_permissions = true;
	}

	if (getuid() != 0 || getgid() != 0) {
		fprintf(stderr, "darlingserver needs to start as root\n");
		exit(1);
	}

	sanitizeProcessState(pipefd);

	// the launcher starts us with the user's supplementary groups
	int groupCount = getgroups(0, NULL);
	if (groupCount >= 0) {
		userGroups.resize(groupCount);
		groupCount = getgroups(groupCount, userGroups.data());
	}
	if (groupCount < 0) {
		fprintf(stderr, "Cannot read your supplementary groups: %s\n", strerror(errno));
		exit(1);
	}
	userGroups.resize(groupCount);

	// Set up /Users in the prefix. It needs no privileges and reads the user's own configuration, so
	// it runs in a child that has dropped root for good.
	if (!runAsUser(originalUID, originalGID, [prefix, originalUID]() { setupUserHome(prefix, originalUID); return true; })) {
		exit(1);
	}
	//setupCoredumpPattern();

	// read the default rlimit so we can restore it for our children
	if (getrlimit(RLIMIT_NOFILE, &default_limit) != 0) {
		fprintf(stderr, "Failed to read default FD rlimit: %s\n", strerror(errno));
		//exit(1);
	} else {
		// ASAN uses a rather obtuse way of closing descriptors for child processes it spawns,
		// and increasing the FD limit screws with it (it tries to close every single descriptor up to the FD limit).
#if !DSERVER_ASAN
		// read the system maximum
		nr_open_file = fopen("/proc/sys/fs/nr_open", "r");
		if (nr_open_file == NULL) {
			fprintf(stderr, "Warning: failed to open /proc/sys/fs/nr_open: %s\n", strerror(errno));
			increased_limit.rlim_cur = increased_limit.rlim_max = default_limit.rlim_max;
			//exit(1);
		} else {
			if (fscanf(nr_open_file, "%lu", &increased_limit.rlim_max) != 1) {
				fprintf(stderr, "Failed to read /proc/sys/fs/nr_open: %s\n", strerror(errno));
				exit(1);
			}
			increased_limit.rlim_cur = increased_limit.rlim_max;
			if (fclose(nr_open_file) != 0) {
				fprintf(stderr, "Failed to close /proc/sys/fs/nr_open: %s\n", strerror(errno));
				exit(1);
			}
		}

		// now set our increased rlimit
		if (setrlimit(RLIMIT_NOFILE, &increased_limit) != 0) {
			// In a rootless user namespace, raising the hard limit can fail.
			// Still raise the soft limit to the inherited hard limit so
			// processes holding numerous descriptors/memfds don't fail with EMFILE.
			increased_limit.rlim_cur = increased_limit.rlim_max = default_limit.rlim_max;
			if (setrlimit(RLIMIT_NOFILE, &increased_limit) != 0) {
				fprintf(stderr, "Warning: failed to increase FD rlimit: %s\n", strerror(errno));
				//exit(1);
			}
		}

#endif
	}

	// the core limit is raised to the maximum once we are no longer root
	if (getrlimit(RLIMIT_CORE, &core_limit) != 0) {
		fprintf(stderr, "Failed to read default core rlimit: %s\n", strerror(errno));
		core_limit.rlim_cur = core_limit.rlim_max = 0;
	} else {
		core_limit.rlim_cur = core_limit.rlim_max;
	}

	// Since overlay cannot be mounted inside user namespaces, we have to setup a new mount namespace
	// and do the mount while we can be root
	if (unshare(CLONE_NEWNS) != 0)
	{
		fprintf(stderr, "Cannot unshare PID and mount namespaces: %s\n", strerror(errno));
		exit(1);
	}

	// systemd marks / as MS_SHARED and the new namespace inherits that, so without this the
	// /dev/shm tmpfs and overlay mounts below would propagate back into the host's namespace.
	if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) != 0)
	{
		fprintf(stderr, "Cannot remount / as slave: %s\n", strerror(errno));
		exit(1);
	}

	int shmMountFlags = MS_NOSUID | MS_NODEV;
	// Workaround for dumb Microsoft bug: https://github.com/microsoft/WSL/issues/8777
	if (!isOnWsl1())
	{
		shmMountFlags |= MS_NOEXEC;
	}

	umount("/dev/shm");
	if (mount("tmpfs", "/dev/shm", "tmpfs", shmMountFlags, NULL) != 0)
	{
		fprintf(stderr, "Cannot mount new /dev/shm: %s\n", strerror(errno));
		exit(1);
	}

	// Pin the prefix only now, inside the new mount namespace. A descriptor opened before unshare()
	// refers to a mount of the host's namespace, and the kernel takes an overlay upper directory and
	// an MS_MOVE target named through /proc/self/fd only from the caller's own namespace. Nothing
	// above follows a path the user controls as root: unshare() and the / and /dev/shm mounts name
	// root-owned host paths only, and /Users is set up with the user's ids.
	PinnedPrefix pinnedPrefix = pinPrefix(prefix, originalUID, originalGID);
	const int prefixFd = pinnedPrefix.fd;

	FsMode fsMode = resolveFsMode(prefix, prefixFd, originalUID, originalGID);

	// This is executed once at prefix creation. The directories are created in the prefix itself, which
	// is the upper layer of the overlay modes, before anything is mounted on it.
	if (fix_permissions && !mirrorDirectoriesIntoPrefix(prefixFd, originalUID, originalGID)) {
		fprintf(stderr, "Cannot create the prefix's directories\n");
		exit(1);
	}

	// Failing to assemble the prefix exits with EX_UNAVAILABLE, which lets the darling client offer a different mode.
	if (fsMode == FsMode::Overlayfs || fsMode == FsMode::FuseOverlayfs) {
		int workFd = openOverlayWorkDir(pinnedPrefix, originalUID, originalGID);
		if (workFd < 0) {
			exit(EX_UNAVAILABLE);
		}
		mergedFd = (fsMode == FsMode::Overlayfs) ? mountOverlayfs(prefixFd, workFd) : mountFuseOverlayfs(prefixFd, workFd);
		close(workFd);
		if (mergedFd < 0) {
			fprintf(stderr, "Cannot mount %s onto %s\n", (fsMode == FsMode::Overlayfs) ? "an overlay" : "fuse-overlayfs", prefix);
			exit(EX_UNAVAILABLE);
		}
	} else {
		mergedFd = copyIntoPrefix(prefixFd);
		if (mergedFd < 0) {
			exit(1);
		}
	}

	// temporarily drop privileges and do some prefix work
	temp_drop_privileges(originalUID, originalGID);
	darlingPreInit(prefix);
	regain_privileges();

	// Tell the parent we're ready
	write(pipefd, ".", 1);
	close(pipefd);

	setsid();

	// launchd's process reports through [0] that its setup is done; the server gives it the green light through [1].
	// Either side sees end-of-file instead if the other one exits first.
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, childWaitFDs) != 0) {
		std::cerr << "Failed to create the socket pair for launchd's process: " << strerror(errno) << std::endl;
		exit(1);
	}

	// we have to use `clone` rather than `fork` to create the process in its own PID namespace
	// and still be able to spawn new processes and threads of our own
	launchdGlobalPID = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, NULL, NULL, NULL, 0);

	if (launchdGlobalPID < 0) {
		fprintf(stderr, "Failed to fork to start launchd: %s\n", strerror(errno));
		exit(1);
	} else if (launchdGlobalPID == 0) {
		// this is the child
		close(childWaitFDs[1]);

		// Detach launchd into its own session + process group, so that any
		// signals it (or its children) broadcast via kill(0/-1, ...) or
		// killpg(0, ...) do not propagate back up to darlingserver / darling /
		// timeout (which all share the same pgrp by default). On ARM64 we
		// observed launchd's startup broadcasting SIGTRAP, killing the parents.
		if (setsid() == (pid_t)-1) {
			fprintf(stderr, "Warning: setsid() failed before launchd: %s\n", strerror(errno));
			// continue anyway
		}

		// mount procfs for our new PID namespace, on the assembled prefix's /proc (through descriptors)
		int procFd = openat(mergedFd, "proc", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (procFd < 0 || mount("proc", procFdPath(procFd).c_str(), "proc", 0, "") != 0)
		{
			fprintf(stderr, "Cannot mount procfs: %s\n", strerror(errno));
			exit(1);
		}
		close(procFd);
		close(mergedFd);
		close(prefixFd);

		// drop our privileges now
		perma_drop_privileges(originalUID, originalGID);
		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		umask(userUmask);
		if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
			fprintf(stderr, "Warning: failed to increase core limit for launchd: %s\n", strerror(errno));
		}

		// decrease the FD limit back to the default
		if (setrlimit(RLIMIT_NOFILE, &default_limit) != 0) {
			fprintf(stderr, "Warning: failed to decrease FD limit back down for launchd: %s\n", strerror(errno));
			//exit(1);
		}

		// launchd is the first process of the container's pid namespace; when it dies, the kernel
		// kills every other process in the container. Tie its life to ours, so that the container
		// does not outlive the server that every process in it talks to.
		// This has to come after the privilege drop above: changing ids clears the parent-death signal.
		// There is no getppid() check for a server that died before this point: our parent is outside
		// the namespace and getppid() returns 0 here. The end-of-file check on the socket pair below
		// covers that case.
		if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
			fprintf(stderr, "Warning: failed to tie launchd to the server's life: %s\n", strerror(errno));
		}

		// tell the parent that our namespace is set up
		if (!sendReadyByte(childWaitFDs[0])) {
			exit(1);
		}

		// wait for the parent to give us the green light; without it, the server is not there
		if (!readReadyByte(childWaitFDs[0])) {
			fprintf(stderr, "darlingserver did not start; not starting launchd\n");
			exit(1);
		}
		close(childWaitFDs[0]);

		spawnLaunchd(prefix);
		__builtin_unreachable();
	}

	// this is the parent
	close(childWaitFDs[0]);
	close(mergedFd);
	close(prefixFd);

	// without launchd there is nothing to serve: every launcher call would wait for it in vain
	if (!readReadyByte(childWaitFDs[1])) {
		fprintf(stderr, "launchd's process failed to set up its namespace\n");
		exit(1);
	}

	// drop our privileges
	perma_drop_privileges(originalUID, originalGID);
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	umask(userUmask);
	if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
		fprintf(stderr, "Warning: failed to increase core limit: %s\n", strerror(errno));
	}

	// a client can exit while we are writing to one of its pipes or sockets;
	// that must fail with EPIPE instead of killing the server.
	// this is done only here, after launchd's process has been created, because an ignored
	// SIGPIPE survives execve() and launchd (and every process it spawns) must start with the default.
	signal(SIGPIPE, SIG_IGN);

#if DSERVER_ASAN
	// set up a signal handler to print leak info
	struct sigaction leak_info_action;
	leak_info_action.sa_handler = handle_sigusr1;
	leak_info_action.sa_flags = SA_RESTART;
	sigemptyset(&leak_info_action.sa_mask);
	sigaction(SIGUSR1, &leak_info_action, NULL);
#endif

	// our IDs no longer change, so the credentials sent with every message can be cached
	DarlingServer::Message::initializeServerCredentials();

	// create the server
	auto server = new DarlingServer::Server(prefix);

	detachStdio();

	// tell the child to go ahead; the socket has been created
	sendReadyByte(childWaitFDs[1]);
	close(childWaitFDs[1]);

	// start the main loop
	server->start();

	// this should never happen
	std::cerr << "Server exited main loop!" << std::endl;
	delete server;

	return 1;
};
