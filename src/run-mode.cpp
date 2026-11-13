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

#include <climits>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/capability.h>

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

Mode classify(bool initialNamespace, bool rootId, bool capabilities) {
	if (!initialNamespace) {
		return Mode::Rootless;
	}
	return (rootId || capabilities) ? Mode::Root : Mode::NonRoot;
}

Mode detect() {
	std::string uidMap;
	{
		std::ifstream file("/proc/self/uid_map");
		std::stringstream contents;
		contents << file.rdbuf();
		uidMap = contents.str();
	}
	// without the map, assume the host's namespace, the one where privileges mean something
	bool initialNamespace = uidMap.empty() || isInitialUserNamespace(uidMap);

	uid_t ruid, euid, suid;
	bool rootId = getresuid(&ruid, &euid, &suid) != 0 || ruid == 0 || euid == 0 || suid == 0;

	struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2] = {};
	bool capabilities = syscall(SYS_capget, &header, data) != 0 || data[0].effective != 0 || data[1].effective != 0;

	return classify(initialNamespace, rootId, capabilities);
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
