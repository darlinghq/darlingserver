// Copyright (C) 2026 Lubos Dolezel
//
// Runs wipeDir() and darlingPreInit() of src/darlingserver.cpp, cut out by
// tests/host/extract-static.sh into the file named by PREFIX_PREINIT_INC, on prefixes created in the
// private directory given as the argument: /var/tmp keeps its files across container starts, as on
// macOS, while /var/run is emptied without following symbolic links out of it.
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include PREFIX_PREINIT_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static void writeFile(const std::string& path, const char* content) {
	FILE* f = fopen(path.c_str(), "w");
	if (f) {
		fputs(content, f);
		fclose(f);
	}
}

static std::string readFile(const std::string& path) {
	char buf[256] = {};
	FILE* f = fopen(path.c_str(), "r");
	if (!f)
		return "<missing>";
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	return std::string(buf, n);
}

static bool isEmptyDir(const std::string& path) {
	DIR* d = opendir(path.c_str());
	if (!d)
		return false;
	int entries = 0;
	while (struct dirent* e = readdir(d))
		if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
			entries++;
	closedir(d);
	return entries == 0;
}

// `varLink`: the prefix's var is a symbolic link to private/var, as in an installed prefix
static void checkLayout(const std::string& base, bool varLink) {
	std::string prefix = base + (varLink ? "/linked" : "/direct");
	std::string var = prefix + (varLink ? "/private/var" : "/var");
	std::string outside = prefix + "-outside";
	mkdir(prefix.c_str(), 0700);
	if (varLink) {
		mkdir((prefix + "/private").c_str(), 0700);
		symlink("private/var", (prefix + "/var").c_str());
	}
	mkdir(var.c_str(), 0700);
	mkdir((var + "/tmp").c_str(), 0700);
	mkdir((var + "/tmp/nested").c_str(), 0700);
	mkdir((var + "/run").c_str(), 0700);
	mkdir(outside.c_str(), 0700);
	writeFile(var + "/tmp/saved", "kept");
	writeFile(var + "/tmp/nested/saved", "kept too");
	writeFile(outside + "/sentinel", "untouched");

	const char* layout = varLink ? " (var -> private/var)" : " (plain var)";
	for (int start = 1; start <= 2; start++) {
		mkdir((var + "/run/daemon").c_str(), 0700);
		writeFile(var + "/run/daemon/pid", "123");
		writeFile(var + "/run/stale.pid", "456");
		symlink(outside.c_str(), (var + "/run/link-out").c_str());

		darlingPreInit(prefix.c_str());

		std::string n = " after start " + std::to_string(start) + layout;
		CHECK(readFile(var + "/tmp/saved") == "kept", ("a file in /var/tmp is kept" + n).c_str());
		CHECK(readFile(var + "/tmp/nested/saved") == "kept too", ("a nested file in /var/tmp is kept" + n).c_str());
		CHECK(isEmptyDir(var + "/run"), ("/var/run is emptied" + n).c_str());
		CHECK(readFile(outside + "/sentinel") == "untouched", ("a symbolic link in /var/run is removed, not followed" + n).c_str());
	}
}

int main(int argc, char** argv) {
	if (argc != 2) {
		std::fprintf(stderr, "usage: %s <private-directory>\n", argv[0]);
		return 2;
	}
	checkLayout(argv[1], false);
	checkLayout(argv[1], true);

	if (fails) {
		std::printf("%d check(s) failed\n", fails);
		return 1;
	}
	std::printf("all checks passed\n");
	return 0;
}
