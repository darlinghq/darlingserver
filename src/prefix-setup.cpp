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

#include <darlingserver/prefix-setup.hpp>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace DarlingServer::PrefixSetup {

namespace {

// A directory listing with its own file offset, so that the descriptor it was opened from can still
// be used for *at() calls.
class DirList {
	DIR* _dir = nullptr;
public:
	explicit DirList(int dirFd) {
		int fd = openat(dirFd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd >= 0) {
			_dir = fdopendir(fd);
			if (!_dir) {
				close(fd);
			}
		}
	}
	~DirList() {
		if (_dir) {
			closedir(_dir);
		}
	}
	DirList(const DirList&) = delete;
	DirList& operator=(const DirList&) = delete;

	bool ok() const { return _dir != nullptr; }
	int fd() const { return dirfd(_dir); }

	// The next name other than "." and "..", or nullptr at the end or on error (errno tells them apart).
	const char* next() {
		for (;;) {
			errno = 0;
			struct dirent* ent = readdir(_dir);
			if (!ent) {
				return nullptr;
			}
			if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
				return ent->d_name;
			}
		}
	}
};

class Fd {
	int _fd;
public:
	explicit Fd(int fd = -1): _fd(fd) {}
	~Fd() {
		if (_fd >= 0) {
			close(_fd);
		}
	}
	Fd(const Fd&) = delete;
	Fd& operator=(const Fd&) = delete;
	int get() const { return _fd; }
	bool ok() const { return _fd >= 0; }
};

std::string join(const std::string& dir, const char* name) {
	return dir.empty() ? std::string(name) : dir + "/" + name;
}

// What the owner of the upper tree can cause by changing it while root works in it: the name is
// gone, now exists, or is not of the kind it was a moment ago.
bool changedMeanwhile(int error) {
	return error == ENOENT || error == EEXIST || error == ELOOP || error == ENOTDIR || error == EISDIR || error == ENOTEMPTY;
}

void skipped(const std::string& path, const char* why) {
	fprintf(stderr, "Skipping %s in the prefix: %s\n", path.c_str(), why);
}

bool failed(const char* what, const std::string& path) {
	fprintf(stderr, "Cannot %s %s: %s\n", what, path.c_str(), strerror(errno));
	return false;
}

int compareTimespec(const struct timespec& a, const struct timespec& b) {
	if (a.tv_sec != b.tv_sec) {
		return (a.tv_sec > b.tv_sec) ? 1 : -1;
	} else if (a.tv_nsec != b.tv_nsec) {
		return (a.tv_nsec > b.tv_nsec) ? 1 : -1;
	}
	return 0;
}

std::string procFdPath(int fd) {
	return "/proc/self/fd/" + std::to_string(fd);
}

void mirrorBelow(int lowerFd, int upperFd, const std::string& path) {
	DirList lower(lowerFd);
	if (!lower.ok()) {
		failed("read", path.empty() ? std::string("the lower directory") : path);
		return;
	}

	while (const char* name = lower.next()) {
		std::string childPath = join(path, name);
		struct stat from;
		if (fstatat(lower.fd(), name, &from, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(from.st_mode)) {
			continue;
		}

		bool created = mkdirat(upperFd, name, 0700) == 0;
		if (!created && errno != EEXIST) {
			failed("create", childPath);
			continue;
		}

		// Whatever is there now, only a real directory is entered.
		Fd upper(openat(upperFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
		if (!upper.ok()) {
			if (!changedMeanwhile(errno)) {
				failed("open", childPath);
			}
			continue;
		}
		Fd lowerChild(openat(lower.fd(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
		if (lowerChild.ok()) {
			mirrorBelow(lowerChild.get(), upper.get(), childPath);
		}

		// After the subdirectories, as the lower mode may not let the user create them.
		struct stat now;
		if (created && fstat(upper.get(), &now) == 0 && now.st_uid == geteuid() && fchmod(upper.get(), from.st_mode & ALLPERMS) != 0) {
			failed("set the permissions of", childPath);
		}
	}
	if (errno != 0) {
		failed("read", path);
	}
}

bool copyBelow(int lowerFd, int upperFd, const std::string& path);

// Whether the copy gives files the owners of the lower ones. Only root can; the copy is made by one
// thread, and this is set once before it starts. Without it the files belong to whoever copies, and
// the set-ID bits, which would then name that user rather than the lower owner, are not kept.
bool keepOwners = true;

mode_t copiedMode(mode_t lowerMode) {
	mode_t mode = lowerMode & ALLPERMS;
	return keepOwners ? mode : (mode & ~(S_ISUID | S_ISGID));
}

// Owner and times of a symbolic link, through a descriptor of the link itself.
bool setLinkAttributes(int upperFd, const char* name, const struct stat& from, const std::string& path) {
	Fd link(openat(upperFd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC));
	struct stat st;
	if (!link.ok() || fstat(link.get(), &st) != 0) {
		if (!link.ok() && changedMeanwhile(errno)) {
			skipped(path, "it changed while being updated");
			return true;
		}
		return failed("open", path);
	}
	if (!S_ISLNK(st.st_mode)) {
		skipped(path, "it changed while being updated");
		return true;
	}
	if (keepOwners && fchownat(link.get(), "", from.st_uid, from.st_gid, AT_EMPTY_PATH) != 0) {
		return failed("set the owner of", path);
	}
	const struct timespec times[] = { from.st_atim, from.st_mtim };
	// Kernels that do not take AT_EMPTY_PATH here refuse it with EINVAL; the times of a link are
	// then left alone rather than set by name.
	if (utimensat(link.get(), "", times, AT_EMPTY_PATH) != 0 && errno != EINVAL) {
		return failed("set the times of", path);
	}
	return true;
}

// The attributes of an existing regular file whose modification time matches the lower file's.
// Its contents are not known to be the lower file's, so it never gets a set-ID bit, and a file with
// other links is left alone, as changing it would change files elsewhere.
bool updateFileAttributes(int upperFd, const char* name, const struct stat& from, const struct stat& to, const std::string& path) {
	mode_t mode = from.st_mode & ALLPERMS & ~(S_ISUID | S_ISGID);
	if (keepOwners && to.st_uid == from.st_uid && to.st_gid == from.st_gid && (to.st_mode & ALLPERMS) == (from.st_mode & ALLPERMS)) {
		return true;
	}
	if (!keepOwners && (to.st_mode & ALLPERMS) == mode) {
		return true;
	}

	Fd file(openat(upperFd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC));
	struct stat st;
	if (!file.ok() || fstat(file.get(), &st) != 0) {
		if (!file.ok() && changedMeanwhile(errno)) {
			skipped(path, "it changed while being updated");
			return true;
		}
		return failed("open", path);
	}
	if (!S_ISREG(st.st_mode)) {
		skipped(path, "it changed while being updated");
		return true;
	}
	if (st.st_nlink != 1) {
		skipped(path, "it has other hard links");
		return true;
	}

	// An O_PATH descriptor takes neither fchmod() nor futimens(); its /proc/self/fd entry leads to
	// this very file.
	std::string self = procFdPath(file.get());
	const struct timespec times[] = { from.st_atim, from.st_mtim };
	if (keepOwners && fchownat(file.get(), "", from.st_uid, from.st_gid, AT_EMPTY_PATH) != 0) {
		return failed("set the owner of", path);
	}
	if (chmod(self.c_str(), mode) != 0) {
		return failed("set the permissions of", path);
	}
	if (utimensat(AT_FDCWD, self.c_str(), times, 0) != 0) {
		return failed("set the times of", path);
	}
	return true;
}

bool copyFile(int lowerFd, int upperFd, const char* name, const struct stat& from, const std::string& path) {
	Fd in(openat(lowerFd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
	if (!in.ok()) {
		return failed("read", path);
	}
	// A new file that nobody else can open until it is complete.
	Fd out(openat(upperFd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
	if (!out.ok()) {
		if (changedMeanwhile(errno)) {
			skipped(path, "it changed while being copied");
			return true;
		}
		return failed("create", path);
	}

	std::vector<char> buffer(1 << 16);
	for (;;) {
		ssize_t got = read(in.get(), buffer.data(), buffer.size());
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			if (got < 0) {
				failed("read", path);
				unlinkat(upperFd, name, 0);
				return false;
			}
			break;
		}
		for (ssize_t done = 0; done < got; ) {
			ssize_t put = write(out.get(), buffer.data() + done, got - done);
			if (put < 0 && errno == EINTR) {
				continue;
			}
			if (put <= 0) {
				failed("write", path);
				// a partial copy would look newer than the lower file and never be replaced
				unlinkat(upperFd, name, 0);
				return false;
			}
			done += put;
		}
	}

	// The owner first: changing it clears set-ID bits, which the mode then sets.
	const struct timespec times[] = { from.st_atim, from.st_mtim };
	if (keepOwners && fchown(out.get(), from.st_uid, from.st_gid) != 0) {
		return failed("set the owner of", path);
	}
	if (fchmod(out.get(), copiedMode(from.st_mode)) != 0) {
		return failed("set the permissions of", path);
	}
	if (futimens(out.get(), times) != 0) {
		return failed("set the times of", path);
	}
	return true;
}

bool copySymlink(int lowerFd, int upperFd, const char* name, const struct stat& from, const std::string& path) {
	std::vector<char> target(from.st_size > 0 ? from.st_size + 1 : 4096);
	ssize_t len = readlinkat(lowerFd, name, target.data(), target.size());
	if (len < 0 || (size_t)len >= target.size()) {
		return failed("read the link", path);
	}
	target[len] = '\0';

	if (symlinkat(target.data(), upperFd, name) != 0) {
		if (changedMeanwhile(errno)) {
			skipped(path, "it changed while being copied");
			return true;
		}
		return failed("create", path);
	}
	return setLinkAttributes(upperFd, name, from, path);
}

bool copyDirectory(int lowerFd, int upperFd, const char* name, const struct stat& from, bool exists, const std::string& path) {
	bool created = false;
	if (!exists) {
		if (mkdirat(upperFd, name, 0700) == 0) {
			created = true;
		} else if (errno != EEXIST) {
			return failed("create", path);
		}
	}

	Fd upper(openat(upperFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
	if (!upper.ok()) {
		if (changedMeanwhile(errno)) {
			skipped(path, "it is not a directory");
			return true;
		}
		return failed("open", path);
	}

	if (created) {
		// Only the directory made here gets the lower attributes, not one put in its place.
		struct stat now;
		if (fstat(upper.get(), &now) != 0) {
			return failed("open", path);
		}
		created = now.st_uid == geteuid();
		if (created && ((keepOwners && fchown(upper.get(), from.st_uid, from.st_gid) != 0) || fchmod(upper.get(), copiedMode(from.st_mode)) != 0)) {
			return failed("set the owner and permissions of", path);
		}
	}

	Fd lower(openat(lowerFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
	if (!lower.ok()) {
		return failed("read", path);
	}
	if (!copyBelow(lower.get(), upper.get(), path)) {
		return false;
	}

	// The times last, as filling the directory changed them.
	const struct timespec times[] = { from.st_atim, from.st_mtim };
	if (created && futimens(upper.get(), times) != 0) {
		return failed("set the times of", path);
	}
	return true;
}

bool copyEntry(int lowerFd, int upperFd, const char* name, const std::string& path) {
	struct stat from, to;
	if (fstatat(lowerFd, name, &from, AT_SYMLINK_NOFOLLOW) != 0) {
		return failed("read", path);
	}
	bool exists = fstatat(upperFd, name, &to, AT_SYMLINK_NOFOLLOW) == 0;
	if (!exists && errno != ENOENT) {
		return failed("look at", path);
	}

	if (S_ISDIR(from.st_mode)) {
		if (exists && !S_ISDIR(to.st_mode)) {
			return true;
		}
		return copyDirectory(lowerFd, upperFd, name, from, exists, path);
	}

	if (!S_ISREG(from.st_mode) && !S_ISLNK(from.st_mode)) {
		skipped(path, "only directories, files and symbolic links are copied");
		return true;
	}

	if (exists) {
		if ((from.st_mode & S_IFMT) != (to.st_mode & S_IFMT)) {
			return true;
		}
		int newer = compareTimespec(from.st_mtim, to.st_mtim);
		if (newer < 0) {
			// the prefix has a newer one; keep it
			return true;
		} else if (newer == 0) {
			// presumably the same; refresh the attributes in case they changed
			return S_ISREG(from.st_mode) ? updateFileAttributes(upperFd, name, from, to, path) : setLinkAttributes(upperFd, name, from, path);
		}
		if (unlinkat(upperFd, name, 0) != 0) {
			if (changedMeanwhile(errno)) {
				skipped(path, "it changed while being replaced");
				return true;
			}
			return failed("remove the old", path);
		}
	}

	return S_ISREG(from.st_mode) ? copyFile(lowerFd, upperFd, name, from, path) : copySymlink(lowerFd, upperFd, name, from, path);
}

bool copyBelow(int lowerFd, int upperFd, const std::string& path) {
	DirList lower(lowerFd);
	if (!lower.ok()) {
		return failed("read", path.empty() ? std::string("the lower directory") : path);
	}
	while (const char* name = lower.next()) {
		if (!copyEntry(lower.fd(), upperFd, name, join(path, name))) {
			return false;
		}
	}
	if (errno != 0) {
		return failed("read", path);
	}
	return true;
}

}

bool isPlainOptionPath(std::string_view path) {
	if (path.empty() || path[0] != '/') {
		return false;
	}
	for (unsigned char c: path) {
		if (c < 0x20 || c == 0x7f || c == ',' || c == ':' || c == '\\') {
			return false;
		}
	}
	return true;
}

bool splitPath(std::string_view path, std::string& parent, std::string& name) {
	if (path.empty() || path[0] != '/') {
		return false;
	}
	size_t end = path.find_last_not_of('/');
	if (end == std::string_view::npos) {
		return false;
	}
	std::string_view trimmed = path.substr(0, end + 1);
	size_t slash = trimmed.rfind('/');
	std::string_view last = trimmed.substr(slash + 1);
	if (last == "." || last == "..") {
		return false;
	}
	std::string_view dir = trimmed.substr(0, slash);
	size_t dirEnd = dir.find_last_not_of('/');
	parent = (dirEnd == std::string_view::npos) ? std::string("/") : std::string(dir.substr(0, dirEnd + 1));
	name = std::string(last);
	return true;
}

bool prefixDirAcceptable(const struct stat& st, uid_t uid, gid_t gid) {
	if (!S_ISDIR(st.st_mode) || st.st_uid != uid) {
		return false;
	}
	if (st.st_mode & S_IWOTH) {
		return false;
	}
	return !(st.st_mode & S_IWGRP) || st.st_gid == gid;
}

bool workDirAcceptable(const struct stat& st, uid_t uid) {
	if (!S_ISDIR(st.st_mode)) {
		return false;
	}
	if (st.st_uid == uid) {
		return true;
	}
	return st.st_uid == 0 && !(st.st_mode & (S_IWGRP | S_IWOTH));
}

bool privateRootDirAcceptable(const struct stat& st) {
	return S_ISDIR(st.st_mode) && st.st_uid == 0 && !(st.st_mode & (S_IRWXG | S_IRWXO));
}

void mirrorDirectories(int lowerFd, int upperFd) {
	mirrorBelow(lowerFd, upperFd, "");
}

bool copyTree(int lowerFd, int upperFd, bool giveLowerOwners) {
	keepOwners = giveLowerOwners;
	return copyBelow(lowerFd, upperFd, "");
}

bool findUserDir(std::string_view contents, std::string_view name, std::string_view home, std::string& dir) {
	std::string key = "XDG_" + std::string(name) + "_DIR=";
	bool found = false;

	while (!contents.empty()) {
		size_t eol = contents.find('\n');
		std::string_view line = contents.substr(0, eol);
		contents = (eol == std::string_view::npos) ? std::string_view() : contents.substr(eol + 1);

		size_t start = line.find_first_not_of(" \t");
		if (start == std::string_view::npos || line[start] == '#') {
			continue;
		}
		line = line.substr(start);
		if (line.substr(0, key.size()) != key) {
			continue;
		}
		line = line.substr(key.size());

		// a double-quoted value, then nothing but blanks
		if (line.empty() || line[0] != '"') {
			continue;
		}
		std::string value;
		size_t i = 1;
		bool closed = false;
		for (; i < line.size(); i++) {
			char c = line[i];
			if (c == '"') {
				closed = true;
				break;
			}
			if (c == '\\' && i + 1 < line.size()) {
				char next = line[i + 1];
				if (next == '"' || next == '\\' || next == '$' || next == '`') {
					value.push_back(next);
					i++;
					continue;
				}
			}
			value.push_back(c);
		}
		if (!closed || line.find_first_not_of(" \t\r", i + 1) != std::string_view::npos) {
			continue;
		}

		static const std::string_view homeVar = "$HOME";
		std::string_view v = value;
		if (v.substr(0, homeVar.size()) == homeVar && (v.size() == homeVar.size() || v[homeVar.size()] == '/')) {
			dir = std::string(home) + std::string(v.substr(homeVar.size()));
		} else if (!v.empty() && v[0] == '/') {
			dir = value;
		} else {
			continue;
		}
		found = true;
	}

	return found;
}

std::string userDirOrDefault(std::string_view contents, std::string_view name, std::string_view home) {
	std::string dir;
	if (findUserDir(contents, name, home, dir)) {
		return dir;
	}
	dir = std::string(home);
	if (name == "DESKTOP") {
		dir += "/Desktop";
	}
	return dir;
}

};
