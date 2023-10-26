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
#include <filesystem>

#include <darling-config.h>

#include <darlingserver/server.hpp>
#include <darlingserver/config.hpp>

#ifndef DARLINGSERVER_INIT_PROCESS
	#define DARLINGSERVER_INIT_PROCESS "/sbin/launchd"
#endif

#ifndef DARLINGSERVER_XDG_USER_DIR_CMD
	#define DARLINGSERVER_XDG_USER_DIR_CMD "xdg-user-dir"
#endif

#if DSERVER_ASAN
	#include <sanitizer/lsan_interface.h>
#endif

// TODO: most of the code here was ported over from startup/darling.c; we should C++-ify it.

void fixPermissionsRecursive(const char* path, uid_t originalUID, gid_t originalGID)
{
	DIR* dir;
	struct dirent* ent;

	if (chown(path, originalUID, originalGID) == -1)
		fprintf(stderr, "Cannot chown %s: %s\n", path, strerror(errno));

	dir = opendir(path);
	if (!dir)
		return;

	while ((ent = readdir(dir)) != NULL)
	{
		if (ent->d_type == DT_DIR)
		{
			char* subdir;

			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;

			subdir = (char*) malloc(strlen(path) + 2 + strlen(ent->d_name));
			sprintf(subdir, "%s/%s", path, ent->d_name);

			fixPermissionsRecursive(subdir, originalUID, originalGID);

			free(subdir);
		}
	}

	closedir(dir);
}

const char* xdgDirectory(const char* name)
{
	static char dir[4096];
	char* cmd = (char*) malloc(sizeof(DARLINGSERVER_XDG_USER_DIR_CMD) + 1 + strlen(name));

	sprintf(cmd, DARLINGSERVER_XDG_USER_DIR_CMD " %s", name);

	FILE* proc = popen(cmd, "r");

	free(cmd);

	if (!proc)
		return NULL;

	fgets(dir, sizeof(dir)-1, proc);

	pclose(proc);

	size_t len = strlen(dir);
	if (len <= 1)
		return NULL;

	if (dir[len-1] == '\n')
		dir[len-1] = '\0';
	return dir;
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
		const char* dir = xdgDirectory(xdgmap[i][0]);
		if (!dir)
			continue;

		snprintf(buf2, sizeof(buf2), "/Volumes/SystemRoot%s", dir);
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

void darlingPreInit(const char* prefix)
{
	// TODO: Run /usr/libexec/makewhatis
	const char* dirs[] = {
		"/var/tmp",
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

void spawnLaunchd(const char* prefix)
{
	puts("Bootstrapping the container with launchd...");

	// putenv("KQUEUE_DEBUG=1");

	auto tmp = (std::string(prefix) + "/.darlingserver.sock");

	const char* initPath = getenv("DSERVER_INIT");

	if (!initPath) {
		initPath = DARLINGSERVER_INIT_PROCESS;
	}

	setenv("DYLD_ROOT_PATH", LIBEXEC_PATH, 1);
	setenv("__mldr_sockpath", tmp.c_str(), 1);
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
		// All WSL systems have WSLENV set by default, while WSL_INTEROP is WSL2-specific.
		result = getenv("WSLENV") && !getenv("WSL_INTEROP");
	}

	return result;
}

static bool shouldUseOverlayFs() {
	bool shouldUse = true;
	bool explicitlySet = false;

	if (testEnvVar("DARLING_NOOVERLAYFS")) {
		shouldUse = false;
		explicitlySet = true;
	} else if (getenv("DARLING_NOOVERLAYFS")) {
		shouldUse = true;
		explicitlySet = true;
	}

	// https://github.com/microsoft/WSL/issues/8748
	// Microsoft is being dumb with its overlayfs implementation and they don't seem to be willing to be fix WSL1-related bugs.
	// We therefore have to enable this hack on WSL1.
	if (!explicitlySet && isOnWsl1()) {
		shouldUse = false;
	}

	return shouldUse;
}

static int compareTimespec(const timespec& a, const timespec& b) {
	if (a.tv_sec != b.tv_sec) {
		return (a.tv_sec > b.tv_sec) ? 1 : -1;
	} else if (a.tv_nsec != b.tv_nsec) {
		return (a.tv_nsec > b.tv_nsec) ? 1 : -1;
	} else {
		return 0;
	}
}

static void copyAndSetAttributes(std::string& fromPath, std::string& toPath) {
	struct stat fromStat, toStat;
	if (lstat(fromPath.c_str(), &fromStat) == -1) {
		fprintf(stderr, "Failed to stat file %s: %s\n", fromPath.c_str(), strerror(errno));
		abort();
	}
	bool destinationExists = true;
	bool updateAttributes = false;
	if (lstat(toPath.c_str(), &toStat) == -1) {
		if (errno != ENOENT) {
			fprintf(stderr, "Failed to stat file %s: %s\n", toPath.c_str(), strerror(errno));
			abort();
		}
		destinationExists = false;
	}

	if (S_ISDIR(fromStat.st_mode)) {
		if (destinationExists && !S_ISDIR(toStat.st_mode)) {
			return;
		} else {
			if (!destinationExists) {
				if (mkdir(toPath.c_str(), fromStat.st_mode & ALLPERMS) == -1) {
					fprintf(stderr, "Failed to create directory %s: %s\n", toPath.c_str(), strerror(errno));
					abort();
				}
				updateAttributes = true;
			}
			DIR* fromDir = opendir(fromPath.c_str());
			if (fromDir == NULL) {
				fprintf(stderr, "Failed to open directory %s: %s\n", fromPath.c_str(), strerror(errno));
				abort();
			}

			struct dirent* entry = NULL;
			while ((errno = 0) || ((entry = readdir(fromDir)) != NULL)) {
				if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
					continue;
				}

				size_t oldFromSize = fromPath.size();
				size_t oldToSize = toPath.size();

				fromPath.push_back('/');
				toPath.push_back('/');

				fromPath.append(entry->d_name);
				toPath.append(entry->d_name);

				copyAndSetAttributes(fromPath, toPath);

				fromPath.resize(oldFromSize);
				toPath.resize(oldToSize);
			}

			if (errno) {
				fprintf(stderr, "Failed to read directory %s: %s\n", fromPath.c_str(), strerror(errno));
				abort();
			}

			if (closedir(fromDir) == -1) {
				fprintf(stderr, "Failed to close directory %s: %s\n", fromPath.c_str(), strerror(errno));
			}
		}
	} else {
		if (destinationExists) {
			if ((fromStat.st_mode & S_IFMT) != (toStat.st_mode & S_IFMT)) {
				return;
			} else {
				int compareResult = compareTimespec(fromStat.st_mtim, toStat.st_mtim);
				// the lower file is older, don't touch the newer file.
				if (compareResult == -1) {
					return;
				// the lower file and the newer files should be the same.
				// we still update the attributes though, in case ownership or permission changes.
				} else if (compareResult == 0) {
					updateAttributes = true;
				} else if (compareResult == 1) {
					if (unlink(toPath.c_str()) == -1) {
						fprintf(stderr, "Failed to delete old destination file %s: %s\n", toPath.c_str(), strerror(errno));
						abort();
					}
					std::filesystem::copy(fromPath, toPath, std::filesystem::copy_options::copy_symlinks);
					updateAttributes = true;
				}
			}
		} else {
			std::filesystem::copy(fromPath, toPath, std::filesystem::copy_options::copy_symlinks);
			updateAttributes = true;
		}
	}

	if (updateAttributes) {
		struct timespec times[] = {
			fromStat.st_atim,
			fromStat.st_mtim
		};
		if (utimensat(-1, toPath.c_str(), times, AT_SYMLINK_NOFOLLOW) == -1) {
			fprintf(stderr, "Failed to set timestamp for %s: %s\n", toPath.c_str(), strerror(errno));
			abort();
    	}
		if (fchownat(-1, toPath.c_str(), fromStat.st_uid, fromStat.st_gid, AT_SYMLINK_NOFOLLOW) == -1) {
			fprintf(stderr, "Failed to set owner for %s: %s\n", toPath.c_str(), strerror(errno));
			abort();
		}
		// POSIX said that AT_SYMLINK_NOFOLLOW is acceptable for links, but on Linux all calls with AT_SYMLINK_NOFOLLOW fails with ENOTSUP.
		if (fchmodat(-1, toPath.c_str(), fromStat.st_mode & ALLPERMS, S_ISLNK(fromStat.st_mode) ? AT_SYMLINK_NOFOLLOW : 0) == -1) {
			if (!(S_ISLNK(fromStat.st_mode) && (errno == ENOTSUP))) {
				fprintf(stderr, "Failed to set permissions for %s: %s\n", toPath.c_str(), strerror(errno));
				abort();
			}
		}
	}
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

static void perma_drop_privileges(uid_t uid, gid_t gid) {
	if (setresgid(gid, gid, gid) < 0) {
		fprintf(stderr, "Failed to drop group privileges\n");
		exit(1);
	}
	if (setresuid(uid, uid, uid) < 0) {
		fprintf(stderr, "Failed to drop user privileges\n");
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
	size_t prefix_length = 0;
	struct rlimit default_limit;
	struct rlimit increased_limit;
	FILE* nr_open_file = NULL;
	int childWaitFDs[2];
	struct rlimit core_limit;

	char *opts;
	char putOld[4096];
	char *p;

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
	sscanf(argv[2], "%d", &originalUID);
	sscanf(argv[3], "%d", &originalGID);
	sscanf(argv[4], "%d", &pipefd);

	if (argv[5][0] == '1') {
		fix_permissions = true;
	}

	prefix_length = strlen(prefix);

	if (getuid() != 0 || getgid() != 0) {
		fprintf(stderr, "darlingserver needs to start as root\n");
		exit(1);
	}

	// temporarily drop privileges to perform some prefix work
	temp_drop_privileges(originalUID, originalGID);
	setupUserHome(prefix, originalUID);
	//setupCoredumpPattern();
	regain_privileges();

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
			fprintf(stderr, "Warning: failed to increase FD rlimit: %s\n", strerror(errno));
			//exit(1);
		}

#endif
	}

	if (getrlimit(RLIMIT_CORE, &core_limit) != 0) {
		fprintf(stderr, "Failed to read default core rlimit: %s\n", strerror(errno));
	} else {
		// increase the core limit to the maximum
		core_limit.rlim_cur = core_limit.rlim_max;

		if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
			fprintf(stderr, "Warning: failed to increase core limit: %s\n", strerror(errno));
		}
	}

	// Since overlay cannot be mounted inside user namespaces, we have to setup a new mount namespace
	// and do the mount while we can be root
	if (unshare(CLONE_NEWNS) != 0)
	{
		fprintf(stderr, "Cannot unshare PID and mount namespaces: %s\n", strerror(errno));
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

	if (shouldUseOverlayFs()) {
		// Because systemd marks / as MS_SHARED and we would inherit this into the overlay mount,
		// causing it not to be unmounted once the init process dies.
		if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) != 0)
		{
			fprintf(stderr, "Cannot remount / as slave: %s\n", strerror(errno));
			exit(1);
		}

		opts = (char*) malloc(strlen(prefix)*2 + sizeof(LIBEXEC_PATH) + 100);

		const char* opts_fmt = "lowerdir=%s,upperdir=%s,workdir=%s.workdir,index=off";

		sprintf(opts, opts_fmt, LIBEXEC_PATH, prefix, prefix);

		// Mount overlay onto our prefix
		if (mount("overlay", prefix, "overlay", 0, opts) != 0)
		{
			if (errno == EINVAL) {
				opts_fmt = "lowerdir=%s,upperdir=%s,workdir=%s.workdir";
				sprintf(opts, opts_fmt, LIBEXEC_PATH, prefix, prefix);
				if (mount("overlay", prefix, "overlay", 0, opts) == 0) {
					goto mount_ok;
				}
			}
			fprintf(stderr, "Cannot mount overlay: %s\n", strerror(errno));
			exit(1);
		}

	mount_ok:
		free(opts);
	} else {
		std::string fromPath = LIBEXEC_PATH;
		std::string toPath = prefix;
		copyAndSetAttributes(fromPath, toPath);
	}

	// This is executed once at prefix creation
	if (fix_permissions) {
		const char* extra_paths[] = {
			"/private/etc/passwd",
			"/private/etc/master.passwd",
			"/private/etc/group",
		};
		char path[4096];

		fixPermissionsRecursive(prefix, originalUID, originalGID);

		path[sizeof(path) - 1] = '\0';
		strncpy(path, prefix, sizeof(path) - 1);
		for (size_t i = 0; i < sizeof(extra_paths) / sizeof(*extra_paths); ++i) {
			path[prefix_length] = '\0';
			strncat(path, extra_paths[i], sizeof(path) - 1);
			fixPermissionsRecursive(path, originalUID, originalGID);
		}
	}

	// temporarily drop privileges and do some prefix work
	temp_drop_privileges(originalUID, originalGID);
	darlingPreInit(prefix);
	regain_privileges();

	// Tell the parent we're ready
	write(pipefd, ".", 1);
	close(pipefd);

	if (pipe(childWaitFDs) != 0) {
		std::cerr << "Failed to create child waiting pipe: " << strerror(errno) << std::endl;
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
		char buf[1];

		close(childWaitFDs[1]);

		snprintf(putOld, sizeof(putOld), "%s/proc", prefix);

		// mount procfs for our new PID namespace
		if (mount("proc", putOld, "proc", 0, "") != 0)
		{
			fprintf(stderr, "Cannot mount procfs: %s\n", strerror(errno));
			exit(1);
		}

		// drop our privileges now
		perma_drop_privileges(originalUID, originalGID);
		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

		// decrease the FD limit back to the default
		if (setrlimit(RLIMIT_NOFILE, &default_limit) != 0) {
			fprintf(stderr, "Warning: failed to decrease FD limit back down for launchd: %s\n", strerror(errno));
			//exit(1);
		}

		// wait for the parent to give us the green light
		read(childWaitFDs[0], buf, 1);
		close(childWaitFDs[0]);

		spawnLaunchd(prefix);
		__builtin_unreachable();
	}

	// this is the parent
	close(childWaitFDs[0]);

	// drop our privileges
	perma_drop_privileges(originalUID, originalGID);
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

#if DSERVER_ASAN
	// set up a signal handler to print leak info
	struct sigaction leak_info_action;
	leak_info_action.sa_handler = handle_sigusr1;
	leak_info_action.sa_flags = SA_RESTART;
	sigemptyset(&leak_info_action.sa_mask);
	sigaction(SIGUSR1, &leak_info_action, NULL);
#endif

	// create the server
	auto server = new DarlingServer::Server(prefix);

	// tell the child to go ahead; the socket has been created
	write(childWaitFDs[1], ".", 1);
	close(childWaitFDs[1]);

	// start the main loop
	server->start();

	// this should never happen
	std::cerr << "Server exited main loop!" << std::endl;
	delete server;

	return 1;
};
