// Runs the real `/proc/<pid>/maps` helpers of src/process.cpp, cut out by tests/host/extract-static.sh
// into the file named by PROCESS_MAPS_INC, against fixed lines and against this process's own maps:
// the text parser, and the PROCMAP_QUERY lookup that must report the same regions as the text.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "procmap-query.h"
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

static std::vector<Region> ownRegions() {
	std::vector<Region> regions;
	for (const auto& line: ownMapsLines()) {
		Region region;
		if (referenceParse(line, region) && line.find("[vsyscall]") == std::string::npos) {
			regions.push_back(region);
		}
	}
	return regions;
}

static int textProtection(const std::string& perms) {
	int protection = 0;
	if (perms.find('r') != std::string::npos) protection |= PROT_READ;
	if (perms.find('w') != std::string::npos) protection |= PROT_WRITE;
	if (perms.find('x') != std::string::npos) protection |= PROT_EXEC;
	return protection;
}

static bool sameRegion(const Region& a, const Region& b) {
	return a.start == b.start && a.end == b.end && a.perms == b.perms && a.offset == b.offset;
}

static void checkProcmapQuery() {
	int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0, "[setup] /proc/self/maps opens");
	struct procmap_query query;
	if (procmapQuery(fd, 0, 0, query) == ENOTTY) {
		std::printf("SKIP the running kernel has no PROCMAP_QUERY\n");
		close(fd);
		return;
	}

	long page = sysconf(_SC_PAGESIZE);
	char* area = (char*)mmap(nullptr, 3 * page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(area != MAP_FAILED, "[setup] mmap three pages");
	CHECK(munmap(area + page, page) == 0, "[setup] unmap the middle page");
	uintptr_t first = (uintptr_t)area, hole = first + page, third = hole + page;

	CHECK(procmapQuery(fd, first, 0, query) == 0 && query.vma_start == first && query.vma_end == hole
		&& procmapProtection(query.vma_flags) == (PROT_READ | PROT_EXEC) && !(query.vma_flags & PROCMAP_QUERY_VMA_SHARED),
		"a covering query reports the region, its end and its protection");
	CHECK(procmapQuery(fd, hole, 0, query) == ENOENT, "a covering query in a hole reports ENOENT");
	CHECK(procmapQuery(fd, hole, PROCMAP_QUERY_COVERING_OR_NEXT_VMA, query) == 0 && query.vma_start == third,
		"a covering-or-next query in a hole reports the following region");

	char* shared = (char*)mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(shared != MAP_FAILED, "[setup] mmap a shared page");
	CHECK(procmapQuery(fd, (uintptr_t)shared, 0, query) == 0 && (query.vma_flags & PROCMAP_QUERY_VMA_SHARED)
		&& procmapProtection(query.vma_flags) == (PROT_READ | PROT_WRITE),
		"a shared writable region is reported as shared and writable");

	// every region of the text must be found the same way at its first and last byte, and the
	// covering-or-next query at its end must report the next region of the text
	auto before = ownRegions();
	std::vector<Region> fromQuery, nextFromQuery;
	std::vector<int> errors;
	for (const auto& region: before) {
		Region found{}, next{};
		int error = procmapQuery(fd, region.start, 0, query);
		if (error == 0) {
			found = {query.vma_start, query.vma_end, "", query.vma_offset};
			int protection = procmapProtection(query.vma_flags);
			found.perms = textProtection(region.perms) == protection && ((query.vma_flags & PROCMAP_QUERY_VMA_SHARED) != 0) == (region.perms.find('s') != std::string::npos) ? region.perms : "mismatch";
			if (procmapQuery(fd, region.end - 1, 0, query) != 0 || query.vma_start != found.start) {
				found.perms = "mismatch at end";
			}
		}
		errors.push_back(error);
		fromQuery.push_back(found);
		int nextError = procmapQuery(fd, region.end, PROCMAP_QUERY_COVERING_OR_NEXT_VMA, query);
		next.start = nextError == 0 ? query.vma_start : 0;
		nextFromQuery.push_back(next);
	}
	auto after = ownRegions();

	// regions that changed while the test ran (heap growth) are skipped
	size_t compared = 0;
	bool allMatch = true, allNextMatch = true;
	for (size_t i = 0; i < before.size(); ++i) {
		bool stable = false;
		for (size_t j = 0; j < after.size(); ++j) {
			if (sameRegion(before[i], after[j])) {
				stable = i + 1 >= before.size() || (j + 1 < after.size() && sameRegion(before[i + 1], after[j + 1]));
				break;
			}
		}
		if (!stable) {
			continue;
		}
		++compared;
		if (errors[i] != 0 || !sameRegion(before[i], fromQuery[i])) {
			std::printf("  query mismatch at %lx-%lx %s (error %d)\n", (unsigned long)before[i].start, (unsigned long)before[i].end, before[i].perms.c_str(), errors[i]);
			allMatch = false;
		}
		uintptr_t expectedNext = i + 1 < before.size() ? before[i + 1].start : 0;
		if (nextFromQuery[i].start != expectedNext) {
			std::printf("  next mismatch after %lx: %lx, expected %lx\n", (unsigned long)before[i].start, (unsigned long)nextFromQuery[i].start, (unsigned long)expectedNext);
			allNextMatch = false;
		}
	}
	CHECK(compared > 5, "[setup] most of this process's regions stayed unchanged");
	CHECK(allMatch, "PROCMAP_QUERY reports every region of /proc/self/maps with the same bounds, offset and protection");
	CHECK(allNextMatch, "a covering-or-next query at a region's end reports the next region of /proc/self/maps");

	munmap(area, page);
	munmap(area + 2 * page, page);
	munmap(shared, page);
	close(fd);
}

int main() {
	checkFixedLines();
	checkOwnMaps();
	checkProcmapQuery();

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
