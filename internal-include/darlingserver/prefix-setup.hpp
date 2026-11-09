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

#ifndef _DARLINGSERVER_PREFIX_SETUP_HPP_
#define _DARLINGSERVER_PREFIX_SETUP_HPP_

#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>

// Helpers for the part of darlingserver's startup that runs as root and assembles the user's prefix.
// They hold no state, so that they can be tested on the host as an ordinary user.
namespace DarlingServer::PrefixSetup {
	// Whether a path can be written into an overlayfs or fuse-overlayfs mount option string as it is.
	// Both parsers split options at ',' and lower layers at ':', and treat '\' as an escape; how
	// escapes are undone differs between kernel versions and fuse-overlayfs, so such paths are
	// refused rather than escaped. Control characters are refused too, and so is anything but an
	// absolute path.
	bool isPlainOptionPath(std::string_view path);

	// Splits an absolute path into the directory holding it and its last component, ignoring
	// trailing slashes ("/a/b/" gives "/a" and "b"). Fails for a relative path, for "/" and for a
	// last component of "." or "..".
	bool splitPath(std::string_view path, std::string& parent, std::string& name);

	// Whether a directory, as opened by the user, may be used as that user's prefix: it must be the
	// user's, and nobody else may be able to change its entries. A group-writable prefix is accepted
	// only with the user's own primary group; the launcher checks further that this group has no
	// other members.
	bool prefixDirAcceptable(const struct stat& st, uid_t uid, gid_t gid);

	// Whether the work directory next to the prefix may be used: it must be the user's, or root's
	// (older launchers created it as root) and then writable by nobody else.
	bool workDirAcceptable(const struct stat& st, uid_t uid);

	// Whether a directory is root's and closed to everybody else.
	bool privateRootDirAcceptable(const struct stat& st);

	// Creates in the directory upperFd every directory of the tree below lowerFd that it lacks, with
	// the permission bits of the lower directory. Existing entries are left as they are, and nothing
	// in the upper tree is followed if it is not a real directory. Run as the user, this makes the
	// directories of the assembled prefix the user's, without root changing any owner. Problems are
	// reported and skipped.
	void mirrorDirectories(int lowerFd, int upperFd);

	// Copies the tree below lowerFd into upperFd (the copy mode). A file or symbolic link replaces an
	// older one of the same kind, gets the attributes of the lower one when both have the same
	// modification time, and is left alone when it is newer or of a different kind. A new directory
	// gets the lower directory's owner, mode and times.
	//
	// The upper tree may be changed by its owner while this runs as root, so every step works on a
	// single name relative to a directory descriptor and never follows a symbolic link; new files are
	// created exclusively, and the attributes of an existing file are changed through a descriptor of
	// that file, never by name. The set-user-ID and set-group-ID bits are only given to a file this
	// call created and filled itself. An entry that changes kind while this runs is skipped.
	// Returns false, after a message, on any other error.
	bool copyTree(int lowerFd, int upperFd);

	// Looks up one of the user's directories (name is "DOWNLOAD", "MUSIC" and so on) in the contents
	// of an xdg-user-dirs configuration file, user-dirs.dirs. Its lines have the form
	// XDG_<NAME>_DIR="$HOME/<path>" or XDG_<NAME>_DIR="/<path>", with backslash escapes inside the
	// quotes; lines starting with '#' are comments, and the last valid line for a name wins.
	// Returns false if no valid line sets the name.
	bool findUserDir(std::string_view contents, std::string_view name, std::string_view home, std::string& dir);

	// What xdg-user-dir prints for a name: the directory the configuration contents set (empty when
	// there is no configuration file), or else its fallback, home with "/Desktop" for "DESKTOP" and
	// home itself for any other name. The caller treats an empty result as no directory.
	std::string userDirOrDefault(std::string_view contents, std::string_view name, std::string_view home);
};

#endif // _DARLINGSERVER_PREFIX_SETUP_HPP_
