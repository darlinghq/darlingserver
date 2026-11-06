// Runs the real `/proc/<pid>/maps` helpers of src/process.cpp, cut out by tests/host/extract-static.sh
// into the file named by PROCESS_MAPS_INC, against fixed lines and against this process's own maps.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include PROCESS_MAPS_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

struct Region {
	uintptr_t start;
	uintptr_t end;
	std::string perms;
	uintptr_t offset;
};

// independent reference parser for "start-end perms offset ..."
static bool referenceParse(const std::string& line, Region& region) {
	std::istringstream in(line);
	char dash;
	in >> std::hex >> region.start >> dash >> region.end >> region.perms >> region.offset;
	return in && dash == '-';
}

static std::vector<std::string> ownMapsLines() {
	std::ifstream file("/proc/self/maps");
	std::vector<std::string> lines;
	std::string line;
	while (std::getline(file, line)) {
		lines.push_back(line);
	}
	return lines;
}

static void checkFixedLines() {
	uintptr_t start = 0, end = 0, offset = 0;
	char perms[8];

	CHECK(parseMapsLine("7f0c8a400000-7f0c8a428000 r--p 00000000 08:01 1234 /usr/lib/libc.so.6", start, end, perms, offset)
		&& start == 0x7f0c8a400000 && end == 0x7f0c8a428000 && strcmp(perms, "r--p") == 0 && offset == 0,
		"a file mapping line is parsed");
	CHECK(parseMapsLine("7f0c8a5d6000-7f0c8a5da000 rw-s 001d5000 00:05 77 /memfd:name with spaces (deleted)", start, end, perms, offset)
		&& start == 0x7f0c8a5d6000 && end == 0x7f0c8a5da000 && strcmp(perms, "rw-s") == 0 && offset == 0x1d5000,
		"a shared mapping with a non-zero offset and spaces in its name is parsed");
	CHECK(parseMapsLine("ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]", start, end, perms, offset)
		&& start == 0xffffffffff600000 && end == 0xffffffffff601000 && strcmp(perms, "--xp") == 0,
		"the highest addresses are parsed without truncation");
	CHECK(parseMapsLine("1000-2000 ---p 0 00:00 0", start, end, perms, offset) && start == 0x1000 && end == 0x2000,
		"an anonymous line is parsed");
	CHECK(!parseMapsLine("", start, end, perms, offset), "an empty line is rejected");
	CHECK(!parseMapsLine("garbage", start, end, perms, offset), "a malformed line is rejected");
	CHECK(!parseMapsLine("1000-2000", start, end, perms, offset), "a line without permissions and offset is rejected");
}

static void checkOwnMaps() {
	auto lines = ownMapsLines();
	CHECK(!lines.empty(), "[setup] /proc/self/maps is readable");

	bool allMatch = true;
	for (const auto& line: lines) {
		Region expected;
		uintptr_t start = 0, end = 0, offset = 0;
		char perms[8];
		if (!referenceParse(line, expected) || !parseMapsLine(line, start, end, perms, offset)
			|| start != expected.start || end != expected.end || offset != expected.offset || expected.perms != perms) {
			std::printf("  mismatch: %s\n", line.c_str());
			allMatch = false;
		}
	}
	CHECK(allMatch, "every line of /proc/self/maps parses like the reference parser");
}

int main() {
	checkFixedLines();
	checkOwnMaps();

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
