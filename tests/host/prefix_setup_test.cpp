// Root-mode prefix setup helpers (src/prefix-setup.cpp, compiled unchanged), run as an ordinary user.
// The argument is a new private directory to work in.
#include <darlingserver/prefix-setup.hpp>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace DarlingServer::PrefixSetup;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static void testOptionPaths() {
	CHECK(isPlainOptionPath("/home/user/.darling"), "an ordinary prefix path is accepted");
	CHECK(isPlainOptionPath("/usr/local/libexec/darling"), "the default lower directory is accepted");
	CHECK(isPlainOptionPath("/home/user/my darling=1/x.workdir"), "spaces and '=' are accepted");
	CHECK(isPlainOptionPath("/proc/self/fd/12"), "a descriptor path is accepted");
	CHECK(!isPlainOptionPath("/home/user/a,upperdir=/etc"), "a comma (option separator) is refused");
	CHECK(!isPlainOptionPath("/home/user/a,"), "a trailing comma is refused");
	CHECK(!isPlainOptionPath("/home/user/a:/root"), "a colon (lower layer separator) is refused");
	CHECK(!isPlainOptionPath("/home/user/a\\,b"), "a backslash (escape) is refused");
	CHECK(!isPlainOptionPath("/home/user/a\nb"), "a newline is refused");
	CHECK(!isPlainOptionPath("/home/user/a\tb"), "a tab is refused");
	CHECK(!isPlainOptionPath("/home/user/a\x7f"), "DEL is refused");
	CHECK(!isPlainOptionPath(std::string("/home/user/a\0b", 14)), "an embedded NUL is refused");
	CHECK(!isPlainOptionPath(""), "an empty path is refused");
	CHECK(!isPlainOptionPath("relative/path"), "a relative path is refused");
	CHECK(isPlainOptionPath("/home/us\xc3\xa9r/.darling"), "UTF-8 bytes are accepted");
}

static void testSplitPath() {
	std::string parent, name;
	CHECK(splitPath("/home/user/.darling", parent, name) && parent == "/home/user" && name == ".darling", "a prefix splits into its directory and name");
	CHECK(splitPath("/home/user/.darling//", parent, name) && parent == "/home/user" && name == ".darling", "trailing slashes are ignored");
	CHECK(splitPath("/home//user//.darling", parent, name) && parent == "/home//user" && name == ".darling", "doubled slashes before the name are dropped");
	CHECK(splitPath("/darling", parent, name) && parent == "/" && name == "darling", "a prefix in / has / as its directory");
	CHECK(!splitPath("/", parent, name), "/ itself is refused");
	CHECK(!splitPath("///", parent, name), "only slashes are refused");
	CHECK(!splitPath("", parent, name), "an empty path is refused");
	CHECK(!splitPath("home/user/.darling", parent, name), "a relative path is refused");
	CHECK(!splitPath("/home/user/..", parent, name), "a last component of .. is refused");
	CHECK(!splitPath("/home/user/.", parent, name), "a last component of . is refused");
}

static struct stat dirStat(uid_t uid, gid_t gid, mode_t mode) {
	struct stat st;
	memset(&st, 0, sizeof(st));
	st.st_uid = uid;
	st.st_gid = gid;
	st.st_mode = S_IFDIR | mode;
	return st;
}

static void testDirChecks() {
	CHECK(prefixDirAcceptable(dirStat(1000, 1000, 0700), 1000, 1000), "a 0700 prefix of the user is accepted");
	CHECK(prefixDirAcceptable(dirStat(1000, 100, 0755), 1000, 1000), "a 0755 prefix of the user is accepted");
	CHECK(prefixDirAcceptable(dirStat(1000, 1000, 0775), 1000, 1000), "a group-writable prefix with the user's own group is accepted");
	CHECK(!prefixDirAcceptable(dirStat(1000, 100, 0775), 1000, 1000), "a group-writable prefix with another group is refused");
	CHECK(!prefixDirAcceptable(dirStat(1000, 1000, 0757), 1000, 1000), "a world-writable prefix is refused");
	CHECK(!prefixDirAcceptable(dirStat(1001, 1000, 0700), 1000, 1000), "another user's prefix is refused");
	CHECK(!prefixDirAcceptable(dirStat(0, 0, 0755), 1000, 1000), "root's directory is refused as a user's prefix");
	CHECK(prefixDirAcceptable(dirStat(0, 0, 0755), 0, 0), "root's own prefix is accepted for root");
	struct stat file = dirStat(1000, 1000, 0700);
	file.st_mode = S_IFREG | 0700;
	CHECK(!prefixDirAcceptable(file, 1000, 1000), "a file is refused as the prefix");

	CHECK(workDirAcceptable(dirStat(1000, 1000, 0755), 1000), "the user's work directory is accepted");
	CHECK(workDirAcceptable(dirStat(0, 0, 0755), 1000), "a 0755 work directory of root (older launchers) is accepted");
	CHECK(!workDirAcceptable(dirStat(0, 0, 0775), 1000), "a group-writable work directory of root is refused");
	CHECK(!workDirAcceptable(dirStat(0, 0, 01777), 1000), "a world-writable work directory of root is refused");
	CHECK(!workDirAcceptable(dirStat(1001, 1001, 0755), 1000), "another user's work directory is refused");

	CHECK(privateRootDirAcceptable(dirStat(0, 0, 0700)), "a 0700 directory of root is private");
	CHECK(!privateRootDirAcceptable(dirStat(0, 0, 0750)), "a group-readable directory of root is not private");
	CHECK(!privateRootDirAcceptable(dirStat(1000, 1000, 0700)), "a user's directory is not root's private one");
}

// test fixtures in the private directory

static std::string base;

static std::string at(const std::string& rel) {
	return base + "/" + rel;
}

static void mkdirs(const std::string& rel, mode_t mode = 0755) {
	if (mkdir(at(rel).c_str(), mode) != 0 || chmod(at(rel).c_str(), mode) != 0) {
		std::perror(rel.c_str());
		std::exit(2);
	}
}

static void writeFile(const std::string& rel, const char* contents, mode_t mode, time_t mtime) {
	int fd = open(at(rel).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, contents, strlen(contents)) != (ssize_t)strlen(contents) || fchmod(fd, mode) != 0) {
		std::perror(rel.c_str());
		std::exit(2);
	}
	struct timespec times[] = { { mtime, 0 }, { mtime, 0 } };
	futimens(fd, times);
	close(fd);
}

static void makeLink(const char* target, const std::string& rel, time_t mtime) {
	if (symlink(target, at(rel).c_str()) != 0) {
		std::perror(rel.c_str());
		std::exit(2);
	}
	struct timespec times[] = { { mtime, 0 }, { mtime, 0 } };
	utimensat(AT_FDCWD, at(rel).c_str(), times, AT_SYMLINK_NOFOLLOW);
}

static std::string readFile(const std::string& rel) {
	std::string contents;
	FILE* f = std::fopen(at(rel).c_str(), "r");
	if (!f) {
		return "<missing>";
	}
	char buf[256];
	size_t n;
	while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
		contents.append(buf, n);
	}
	std::fclose(f);
	return contents;
}

static bool lstatOk(const std::string& rel, struct stat& st) {
	return lstat(at(rel).c_str(), &st) == 0;
}

static bool exists(const std::string& rel) {
	struct stat st;
	return lstatOk(rel, st);
}

static mode_t modeOf(const std::string& rel) {
	struct stat st;
	return lstatOk(rel, st) ? (st.st_mode & 07777) : 0;
}

static std::string linkTarget(const std::string& rel) {
	char buf[256];
	ssize_t n = readlink(at(rel).c_str(), buf, sizeof(buf) - 1);
	return n < 0 ? std::string("<none>") : std::string(buf, n);
}

static int openDir(const std::string& rel) {
	int fd = open(at(rel).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		std::perror(rel.c_str());
		std::exit(2);
	}
	return fd;
}

// What the walks must never touch: a directory outside the upper tree, with a file in it, that
// symbolic links planted in the upper tree point at.
static void makeOutside(const std::string& dir) {
	mkdirs(dir);
	writeFile(dir + "/victim", "untouched", 0600, 1000);
}

static bool outsideUntouched(const std::string& dir, const char* what) {
	struct stat st;
	bool ok = readFile(dir + "/victim") == "untouched" && lstatOk(dir + "/victim", st) && (st.st_mode & 07777) == 0600 && st.st_mtime == 1000;
	// nothing new appeared there either
	ok = ok && !exists(dir + "/sub") && !exists(dir + "/file") && !exists(dir + "/link") && !exists(dir + "/ro");
	CHECK(ok, what);
	return ok;
}

static void testMirror() {
	mkdirs("m");
	mkdirs("m/lower");
	mkdirs("m/lower/sub");
	mkdirs("m/lower/sub/deeper", 0750);
	mkdirs("m/lower/ro");
	mkdirs("m/lower/ro/inner", 0700);
	chmod(at("m/lower/ro").c_str(), 0555);
	mkdirs("m/lower/redirected");
	mkdirs("m/lower/redirected/sub");
	writeFile("m/lower/file", "x", 0644, 1000);
	makeLink("sub", "m/lower/link", 1000);
	mkdirs("m/upper");
	makeOutside("m/outside");
	// where the lower tree has a directory, the user's tree has a link out of it
	makeLink("../outside", "m/upper/redirected", 1000);
	mkdirs("m/upper/sub", 0700);

	int lower = openDir("m/lower"), upper = openDir("m/upper");
	mirrorDirectories(lower, upper);
	close(lower);
	close(upper);

	CHECK(modeOf("m/upper/sub/deeper") == 0750, "a missing directory is created with the lower mode");
	CHECK(modeOf("m/upper/sub") == 0700, "an existing directory keeps its mode");
	CHECK(modeOf("m/upper/ro") == 0555 && modeOf("m/upper/ro/inner") == 0700, "a read-only directory gets its mode after its subdirectories");
	CHECK(!exists("m/upper/file") && !exists("m/upper/link"), "files and links are not mirrored");
	CHECK(linkTarget("m/upper/redirected") == "../outside", "a link in the user's tree stays as it is");
	outsideUntouched("m/outside", "mirroring does not follow a link in the user's tree");
	chmod(at("m/upper/ro").c_str(), 0755);
	chmod(at("m/lower/ro").c_str(), 0755);
}

static void testCopy() {
	mkdirs("c");
	mkdirs("c/lower");
	mkdirs("c/lower/dir", 0750);
	writeFile("c/lower/dir/file", "lower file", 0640, 2000);
	makeLink("file", "c/lower/dir/link", 2000);
	writeFile("c/lower/newer", "lower newer", 0644, 3000);
	writeFile("c/lower/older", "lower older", 0644, 1500);
	writeFile("c/lower/same", "lower same", 0755, 2000);
	writeFile("c/lower/setid", "lower setid", 02755, 2000);
	writeFile("c/lower/setid-same", "lower setid", 02755, 2000);
	writeFile("c/lower/linked", "lower linked", 0644, 2000);
	writeFile("c/lower/kind", "lower kind", 0644, 2000);
	mkdirs("c/lower/redirected");
	writeFile("c/lower/redirected/file", "lower redirected", 0644, 2000);
	writeFile("c/lower/through-link", "lower through", 0644, 3000);
	mkdirs("c/upper");
	makeOutside("c/outside");

	// a stale copy, a newer one, one whose contents are the user's but whose time matches, and links out
	writeFile("c/upper/newer", "stale", 0600, 1000);
	writeFile("c/upper/older", "kept by the user", 0600, 1600);
	writeFile("c/upper/same", "the user's own", 0600, 2000);
	writeFile("c/upper/setid-same", "the user's own", 0644, 2000);
	// a hard link to a file outside, with the time of the lower file
	writeFile("c/outside/hardlinked", "outside", 0600, 2000);
	if (link(at("c/outside/hardlinked").c_str(), at("c/upper/linked").c_str()) != 0) {
		std::perror("link");
		std::exit(2);
	}
	makeLink("../outside", "c/upper/redirected", 2000);
	makeLink("../outside/victim", "c/upper/through-link", 1000);
	mkdirs("c/upper/kind");

	int lower = openDir("c/lower"), upper = openDir("c/upper");
	bool ok = copyTree(lower, upper);
	close(lower);
	close(upper);
	CHECK(ok, "the copy succeeds");

	struct stat st;
	CHECK(readFile("c/upper/dir/file") == "lower file" && modeOf("c/upper/dir/file") == 0640 && lstatOk("c/upper/dir/file", st) && st.st_mtime == 2000,
		"a new file gets the lower contents, mode and time");
	CHECK(modeOf("c/upper/dir") == 0750, "a new directory gets the lower mode");
	CHECK(linkTarget("c/upper/dir/link") == "file", "a new link gets the lower target");
	CHECK(readFile("c/upper/newer") == "lower newer" && lstatOk("c/upper/newer", st) && st.st_mtime == 3000, "an older file is replaced");
	CHECK(readFile("c/upper/older") == "kept by the user" && modeOf("c/upper/older") == 0600, "a newer file is kept");
	CHECK(readFile("c/upper/same") == "the user's own" && modeOf("c/upper/same") == 0755, "a file with the same time gets the lower mode");
	CHECK(modeOf("c/upper/setid") == 02755, "a file copied here keeps the lower set-group-ID bit");
	CHECK(readFile("c/upper/setid-same") == "the user's own" && modeOf("c/upper/setid-same") == 0755,
		"a file not copied here never gets a set-group-ID bit");
	CHECK(readFile("c/outside/hardlinked") == "outside" && lstatOk("c/outside/hardlinked", st) && st.st_nlink == 2 && (st.st_mode & 07777) == 0600,
		"a file with another hard link is left alone");
	CHECK(lstatOk("c/upper/kind", st) && S_ISDIR(st.st_mode), "an entry of another kind is left alone");
	CHECK(linkTarget("c/upper/redirected") == "../outside", "a link where the lower tree has a directory is left alone");
	CHECK(linkTarget("c/upper/through-link") == "../outside/victim", "a link where the lower tree has a file is left alone");
	outsideUntouched("c/outside", "copying does not follow links or hard links in the user's tree");
}

// Without root the owners cannot be given; the set-ID bits, which would name the copier, are dropped.
static void testCopyWithoutOwners() {
	mkdirs("n");
	mkdirs("n/lower");
	mkdirs("n/lower/sub", 02755);
	writeFile("n/lower/sub/setgid", "setgid", 02755, 2000);
	writeFile("n/lower/setuid", "setuid", 04755, 2000);
	writeFile("n/lower/plain", "plain", 0640, 2000);
	// what the user cannot read is left out instead of failing the whole copy (root reads everything)
	writeFile("n/lower/secret", "secret", 0200, 2000);
	mkdirs("n/lower/closed", 0300);
	mkdirs("n/upper");
	int lower = openDir("n/lower"), upper = openDir("n/upper");
	bool ok = copyTree(lower, upper, false);
	chmod(at("n/lower/closed").c_str(), 0755);
	chmod(at("n/lower/secret").c_str(), 0644);
	close(lower);
	close(upper);
	CHECK(ok, "the copy without owners succeeds");
	CHECK(modeOf("n/upper/plain") == 0640 && readFile("n/upper/plain") == "plain", "an ordinary file keeps its mode");
	CHECK(modeOf("n/upper/setuid") == 0755, "the set-user-ID bit is dropped without owners");
	CHECK(modeOf("n/upper/sub/setgid") == 0755, "the set-group-ID bit is dropped without owners");
	CHECK(modeOf("n/upper/sub") == 0755, "a directory loses the set-group-ID bit too");
	if (geteuid() != 0) {
		struct stat st;
		CHECK(!lstatOk("n/upper/secret", st), "a file the user cannot read is not copied");
		CHECK(lstatOk("n/upper/closed", st) && S_ISDIR(st.st_mode), "a directory the user cannot read is created empty");
	}
}

static void testUserDirs() {
	const char* config =
		"# This file is written by xdg-user-dirs-update\n"
		"XDG_DESKTOP_DIR=\"$HOME/Desktop\"\n"
		"XDG_DOWNLOAD_DIR=\"$HOME/Stažené\"\n"
		"  XDG_MUSIC_DIR=\"/data/music\"  \n"
		"XDG_PICTURES_DIR=\"$HOME\"\n"
		"XDG_VIDEOS_DIR=\"$HOME/a \\\"b\\\" \\$c \\\\d\"\n"
		"XDG_DOCUMENTS_DIR=\"$HOMEWORK/x\"\n"
		"XDG_PUBLICSHARE_DIR=\"relative/path\"\n"
		"XDG_TEMPLATES_DIR=\"$HOME/one\"\n"
		"XDG_TEMPLATES_DIR=\"$HOME/two\"\n"
		"XDG_TEMPLATES_DIR=$(touch /tmp/x)\n"
		"#XDG_CACHE_DIR=\"/commented\"\n"
		"XDG_UNCLOSED_DIR=\"$HOME/x\n"
		"XDG_TRAILING_DIR=\"$HOME/x\"; touch /tmp/x\n";
	std::string dir;

	CHECK(findUserDir(config, "DESKTOP", "/home/u", dir) && dir == "/home/u/Desktop", "$HOME is expanded");
	CHECK(findUserDir(config, "DOWNLOAD", "/home/u", dir) && dir == "/home/u/Stažené", "non-ASCII names are kept");
	CHECK(findUserDir(config, "MUSIC", "/home/u", dir) && dir == "/data/music", "an absolute path and surrounding blanks are accepted");
	CHECK(findUserDir(config, "PICTURES", "/home/u", dir) && dir == "/home/u", "$HOME alone is the home directory");
	CHECK(findUserDir(config, "VIDEOS", "/home/u", dir) && dir == "/home/u/a \"b\" $c \\d", "escapes inside the quotes are undone");
	CHECK(!findUserDir(config, "DOCUMENTS", "/home/u", dir), "$HOMEWORK is not $HOME");
	CHECK(!findUserDir(config, "PUBLICSHARE", "/home/u", dir), "a relative path is ignored");
	CHECK(findUserDir(config, "TEMPLATES", "/home/u", dir) && dir == "/home/u/two", "the last valid line wins; an unquoted value is ignored");
	CHECK(!findUserDir(config, "CACHE", "/home/u", dir), "comments are ignored");
	CHECK(!findUserDir(config, "UNCLOSED", "/home/u", dir), "an unclosed quote is ignored");
	CHECK(!findUserDir(config, "TRAILING", "/home/u", dir), "anything after the closing quote makes the line invalid");
	CHECK(!findUserDir(config, "DESK", "/home/u", dir), "a name must match in full");
	CHECK(!findUserDir("", "DESKTOP", "/home/u", dir), "an empty file sets nothing");
	CHECK(findUserDir("XDG_DESKTOP_DIR=\"/d\"", "DESKTOP", "/home/u", dir) && dir == "/d", "a last line without a newline counts");

	// what xdg-user-dir prints, and so what gets linked
	CHECK(userDirOrDefault("", "DOWNLOAD", "/home/u") == "/home/u", "no file: a directory falls back to $HOME");
	CHECK(userDirOrDefault("", "DESKTOP", "/home/u") == "/home/u/Desktop", "no file: the desktop falls back to $HOME/Desktop");
	CHECK(userDirOrDefault(config, "DOCUMENTS", "/home/u") == "/home/u", "an invalid entry falls back to $HOME");
	CHECK(userDirOrDefault("XDG_MUSIC_DIR=\"/m\"\n", "VIDEOS", "/home/u") == "/home/u", "a missing entry falls back to $HOME");
	CHECK(userDirOrDefault("XDG_MUSIC_DIR=\"/m\"\n", "DESKTOP", "/home/u") == "/home/u/Desktop", "a missing desktop entry falls back to $HOME/Desktop");
	CHECK(userDirOrDefault(config, "MUSIC", "/home/u") == "/data/music", "a set entry is used");
	CHECK(userDirOrDefault(config, "PICTURES", "/home/u") == "/home/u", "an entry equal to $HOME is still linked to $HOME");
	CHECK(userDirOrDefault("", "MUSIC", "") == "", "with an empty HOME nothing is printed, so nothing is linked");
}

int main(int argc, char** argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: %s <private directory>\n", argv[0]);
		return 2;
	}

	base = argv[1];
	umask(022);

	testOptionPaths();
	testSplitPath();
	testDirChecks();
	testMirror();
	testCopy();
	testCopyWithoutOwners();
	testUserDirs();

	std::printf("%s\n", fails ? "FAILED" : "all passed");
	return fails ? 1 : 0;
}
