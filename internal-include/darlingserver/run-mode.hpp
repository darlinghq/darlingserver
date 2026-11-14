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

#ifndef _DARLINGSERVER_RUN_MODE_HPP_
#define _DARLINGSERVER_RUN_MODE_HPP_

#include <string>
#include <string_view>
#include <sys/types.h>

namespace DarlingServer::RunMode {
	// How darlingserver was started, decided from what the kernel says about this process and never from
	// anything the user can set.
	//
	//   Root      The process can act as root in the user namespace it shares with the launcher (the
	//             initial one on most hosts, a container's own on others): a real, effective or saved uid
	//             of 0, or an effective capability. Started by the setuid launcher (or by root). The full
	//             prefix setup runs as root, with every access to the user's files made as the user.
	//   Rootless  The process is inside a user namespace the launcher's unprivileged child made for it,
	//             which maps the launcher's user and group only. Whatever it is allowed to do there, it is
	//             allowed only on the user's own behalf; the launcher's namespace sees the user.
	//   NonRoot   No privileges and no namespaces: the prefix is a plain copy owned by the user.
	//
	// Both unprivileged modes give the user nothing they could not do themselves, so settings that the
	// user picks (see resolveLibexecPath) may apply to them, and never to Root. A process whose
	// namespace does not fit either description is Root, which needs root ids and drops them to the
	// user's, so a wrong guess fails rather than keeping privileges.
	enum class Mode {
		Root,
		Rootless,
		NonRoot,
	};

	// Whether the contents of /proc/self/uid_map describe the initial user namespace, which maps every
	// id to itself. Anything else, or contents that cannot be parsed, is not the initial namespace.
	bool isInitialUserNamespace(std::string_view uidMap);

	// Whether the contents of /proc/self/uid_map (or gid_map) are exactly the map the launcher writes for
	// rootless mode: one line mapping id 0 inside to the given id outside, for a single id.
	bool isSingleIdMap(std::string_view map, unsigned int outsideId);

	// Where the parent process (the launcher) is, as far as user namespaces go.
	enum class ParentNamespace {
		Unknown,     // it could not be told
		Same,        // the parent's user namespace is this process's own
		Other,       // the parent is in a different user namespace, or in one this process may not look at
	};

	// The facts the mode is decided from.
	struct Facts {
		// the user namespace is the initial one
		bool initialNamespace;
		ParentNamespace parent;
		// the uid and gid maps each map only the launcher's user (or group) to 0, and the namespace's
		// owner is that user
		bool launcherUserOnly;
		// the real, effective or saved uid is 0
		bool rootId;
		// the effective capability set is not empty
		bool capabilities;
	};

	// The mode for a process with the given facts. In the initial user namespace, or in the launcher's,
	// privileges decide between Root and NonRoot. Rootless needs a namespace other than the launcher's
	// that maps only the launcher's user. Anything else is Root.
	Mode classify(const Facts& facts);

	// Reads the facts of this process and classifies it. uid and gid are the launcher's user and group,
	// as the launcher passed them, in the launcher's namespace. Anything that cannot be determined counts
	// as privileged, so that a failure can only lead to the stricter behaviour.
	Mode detect(uid_t uid, gid_t gid);

	// The libexec directory (the read-only system image the prefix is assembled on) to use. The
	// override, from the DARLING_LIBEXEC_PATH environment variable, is honoured only for the
	// unprivileged modes and only if it is an absolute path without control characters or "." and
	// ".." components; otherwise the directory compiled in is used. Returns false, with the reason in
	// error, if an override is honoured but is not valid.
	bool resolveLibexecPath(Mode mode, const char* override, std::string& path, std::string& error);
};

#endif // _DARLINGSERVER_RUN_MODE_HPP_
