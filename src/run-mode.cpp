/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Lubos Dolezel
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

#include <darlingserver/run-mode.hpp>

#include <darling-config.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/nsfs.h>

namespace DarlingServer::RunMode {

bool isInitialUserNamespace(std::string_view uidMap) {
	// the first line of the initial namespace's map reads "0 0 4294967295", with padding
	size_t eol = uidMap.find('\n');
	std::istringstream line{std::string(uidMap.substr(0, eol))};
	unsigned long long inside, outside, count;
	std::string extra;
	if (!(line >> inside >> outside >> count) || (line >> extra)) {
		return false;
	}
	return inside == 0 && outside == 0 && count == 4294967295ULL;
}

bool isSingleIdMap(std::string_view map, unsigned int outsideId) {
	// exactly "0 <id> 1", with padding and a final newline, and nothing after it
	if (!map.empty() && map.back() == '\n') {
		map.remove_suffix(1);
	}
	if (map.find('\n') != std::string_view::npos) {
		return false;
	}
	std::istringstream line{std::string(map)};
	unsigned long long inside, outside, count;
	std::string extra;
	if (!(line >> inside >> outside >> count) || (line >> extra)) {
		return false;
	}
	return inside == 0 && outside == outsideId && count == 1;
}

Mode classify(const Facts& facts) {
	if (facts.initialNamespace || facts.parent == ParentNamespace::Same) {
		return (facts.rootId || facts.capabilities) ? Mode::Root : Mode::NonRoot;
	}
	if (facts.parent == ParentNamespace::Other && facts.launcherUserOnly) {
		return Mode::Rootless;
	}
	// A namespace that maps more than the launcher's user, such as a container's whose root started
	// the launcher, or one that cannot be told apart from it: privileges there may reach other users'
	// files, so they must be dropped as in Root mode.
	return Mode::Root;
}

static std::string readFile(const char* path) {
	std::ifstream file(path);
	std::stringstream contents;
	contents << file.rdbuf();
	return contents.str();
}

static ParentNamespace parentNamespace() {
	struct stat self, parent;
	if (stat("/proc/self/ns/user", &self) != 0) {
		return ParentNamespace::Unknown;
	}

	pid_t ppid = getppid();
	if (ppid <= 1) {
		return ParentNamespace::Unknown;
	}
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/ns/user", (int) ppid);
	int result = stat(path, &parent);
	int error = errno;
	// the parent exited, and the pid may now be another process's
	if (getppid() != ppid) {
		return ParentNamespace::Unknown;
	}

	if (result == 0) {
		return (self.st_dev == parent.st_dev && self.st_ino == parent.st_ino) ? ParentNamespace::Same : ParentNamespace::Other;
	}
	// The kernel lets a process look at another's namespaces only with the right to ptrace it, which
	// a process in a child namespace never has over its parent in the parent namespace (and a process
	// cannot ask for the parent of its own user namespace either). Being refused therefore says the
	// parent is elsewhere; whether that elsewhere maps more than the user is checked separately.
	return (error == EACCES || error == EPERM) ? ParentNamespace::Other : ParentNamespace::Unknown;
}

// Whether the namespace's owner (the euid of the process that made it) is id 0 inside it, the one id
// the launcher's map has: the user made the namespace for themselves.
static bool ownerIsMappedRoot() {
	int fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	uid_t owner = (uid_t) -1;
	bool ok = ioctl(fd, NS_GET_OWNER_UID, &owner) == 0 && owner == 0;
	close(fd);
	return ok;
}

Mode detect(uid_t uid, gid_t gid) {
	Facts facts{};

	std::string uidMap = readFile("/proc/self/uid_map");
	// without the map, assume the host's namespace, the one where privileges mean something
	facts.initialNamespace = uidMap.empty() || isInitialUserNamespace(uidMap);
	if (!facts.initialNamespace) {
		facts.parent = parentNamespace();
		// a namespace that maps only root is root's, whoever asks for it to be called the user's
		facts.launcherUserOnly = uid != 0 && isSingleIdMap(uidMap, uid) && isSingleIdMap(readFile("/proc/self/gid_map"), gid)
			&& ownerIsMappedRoot();
	}

	uid_t ruid, euid, suid;
	facts.rootId = getresuid(&ruid, &euid, &suid) != 0 || ruid == 0 || euid == 0 || suid == 0;

	struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = {};
	facts.capabilities = syscall(SYS_capget, &header, data) != 0 || data[0].effective != 0 || data[1].effective != 0;

	return classify(facts);
}

bool resolveLibexecPath(Mode mode, const char* override, std::string& path, std::string& error) {
	path = LIBEXEC_PATH;
	if (mode == Mode::Root || !override || !override[0]) {
		return true;
	}

	std::string_view value(override);
	bool valid = value[0] == '/' && value.size() <= PATH_MAX / 2;
	for (size_t start = 1; valid && start <= value.size(); ) {
		size_t end = value.find('/', start);
		std::string_view component = value.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
		if (component == "." || component == "..") {
			valid = false;
		}
		if (end == std::string_view::npos) {
			break;
		}
		start = end + 1;
	}
	for (unsigned char c: value) {
		if (c < 0x20 || c == 0x7f) {
			valid = false;
		}
	}
	if (!valid) {
		error = "DARLING_LIBEXEC_PATH must be an absolute path without control characters or . and .. components";
		return false;
	}

	path = std::string(value);
	while (path.size() > 1 && path.back() == '/') {
		path.pop_back();
	}
	return true;
}

};
