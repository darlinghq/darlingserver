// Root-mode prefix setup helpers (src/prefix-setup.cpp, compiled unchanged), run as an ordinary user.
// The argument is a new private directory to work in.
#include <darlingserver/prefix-setup.hpp>
#include <cstdio>
#include <string>

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

int main(int argc, char** argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: %s <private directory>\n", argv[0]);
		return 2;
	}

	testOptionPaths();

	std::printf("%s\n", fails ? "FAILED" : "all passed");
	return fails ? 1 : 0;
}
