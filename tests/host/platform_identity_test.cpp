// Platform identity (src/platform-identity.cpp, compiled unchanged): the machine-id parser, the
// derivation of the default UUID and serial number, the defaults, which pushes are accepted and
// that a rejected push changes nothing.
#include <darlingserver/platform-identity.hpp>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// a made-up machine ID, and what HMAC-SHA256 keyed with it over Darling's application ID gives,
// computed independently with Python's hmac module:
//   hmac.new(machine_id, app_id, hashlib.sha256).hexdigest()
//   = 625d73ffe89756d76387437fd8f895151a6f38beaf230baba4339bacf7899b2a
static const char machineIDText[] = "5c7b8f3d2a1e4f6081a9c3d7e2b4f610\n";
// the first 16 bytes with the version 4 and variant bits set
static const uint8_t expectedUUID[16] = {
	0x62, 0x5d, 0x73, 0xff, 0xe8, 0x97, 0x46, 0xd7, 0xa3, 0x87, 0x43, 0x7f, 0xd8, 0xf8, 0x95, 0x15,
};
// bytes 16 to 19
static const char expectedSerial[] = "DARLING-1A6F38BE";

static dserver_platform_identity_t emptyPush() {
	dserver_platform_identity_t identity;
	std::memset(&identity, 0, sizeof(identity));
	identity.version = DSERVER_PLATFORM_IDENTITY_VERSION;
	identity.size = sizeof(identity);
	return identity;
}

static const uint8_t pushedUUID[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};

static dserver_platform_identity_t fullPush() {
	dserver_platform_identity_t identity = emptyPush();
	identity.present = DSERVER_PLATFORM_IDENTITY_HAS_ALL;
	std::strcpy(identity.model, "Macmini8,1");
	std::strcpy(identity.product_name, "Macmini8,1");
	std::strcpy(identity.board_id, "Mac-7BA5B2DFE22DDD8C");
	std::strcpy(identity.serial_number, "TESTSERIAL01");
	std::strcpy(identity.mlb_serial_number, "TESTMLBSERIAL00001");
	std::strcpy(identity.cpu_brand_string, "Test CPU @ 3.00GHz");
	identity.memory_size = 8ull << 30;
	std::memcpy(identity.platform_uuid, pushedUUID, 16);
	std::memcpy(identity.provisioning_udid, pushedUUID, 16);
	for (int i = 0; i < 16; ++i) {
		identity.system_id[i] = i + 1;
	}
	for (int i = 0; i < 6; ++i) {
		identity.rom[i] = 0xa0 + i;
	}
	return identity;
}

static bool sameIdentity(const dserver_platform_identity_t& a, const dserver_platform_identity_t& b) {
	return std::memcmp(&a, &b, sizeof(a)) == 0;
}

static uint8_t machineID[16];

// applies `pushed` and checks that it is rejected with `expected` without changing anything
static void checkRejected(const dserver_platform_identity_t& pushed, const char* what) {
	PlatformIdentity identity(machineID);
	identity.apply(fullPush());
	auto old = identity.current();
	int code = identity.apply(pushed);
	if (code != -EINVAL) {
		std::printf("  got %d, expected %d\n", code, -EINVAL);
	}
	CHECK(code == -EINVAL && sameIdentity(old, identity.current()), what);
}

int main(int argc, char** argv) {
	// machine-id(5) parsing
	{
		uint8_t id[16];
		CHECK(PlatformIdentity::parseMachineID(machineIDText, std::strlen(machineIDText), machineID), "machine ID with newline parses");
		CHECK(machineID[0] == 0x5c && machineID[15] == 0x10, "machine ID bytes in order");
		CHECK(PlatformIdentity::parseMachineID(machineIDText, 32, id) && std::memcmp(id, machineID, 16) == 0, "machine ID without newline parses");
		CHECK(PlatformIdentity::parseMachineID("5C7B8F3D2A1E4F6081A9C3D7E2B4F610", 32, id) && std::memcmp(id, machineID, 16) == 0, "upper-case machine ID parses");
		CHECK(!PlatformIdentity::parseMachineID(machineIDText, 31, id), "short machine ID rejected");
		CHECK(!PlatformIdentity::parseMachineID("5c7b8f3d2a1e4f6081a9c3d7e2b4f6100\n", 34, id), "long machine ID rejected");
		CHECK(!PlatformIdentity::parseMachineID("5c7b8f3d2a1e4f6081a9c3d7e2b4f61g", 32, id), "non-hex machine ID rejected");
		CHECK(!PlatformIdentity::parseMachineID("uninitialized\n", 14, id), "uninitialized machine ID rejected");
		CHECK(!PlatformIdentity::parseMachineID("00000000000000000000000000000000", 32, id), "all-zero machine ID rejected");
	}

	// reading the file
	{
		// run-host.sh passes a scratch directory
		std::string path = std::string(argc > 1 ? argv[1] : ".") + "/machine-id";
		FILE* f = std::fopen(path.c_str(), "w");
		std::fputs(machineIDText, f);
		std::fclose(f);
		uint8_t id[16];
		CHECK(PlatformIdentity::readMachineID(path.c_str(), id) && std::memcmp(id, machineID, 16) == 0, "machine ID file read");
		f = std::fopen(path.c_str(), "w");
		std::fputs("5c7b8f3d2a1e4f6081a9c3d7e2b4f610\nextra\n", f);
		std::fclose(f);
		CHECK(!PlatformIdentity::readMachineID(path.c_str(), id), "machine ID file with trailing data rejected");
		std::remove(path.c_str());
		CHECK(!PlatformIdentity::readMachineID(path.c_str(), id), "missing machine ID file reported");
	}

	// derivation (machine-id(5) application-specific ID scheme)
	{
		uint8_t uuid[16];
		char serial[DSERVER_PLATFORM_IDENTITY_STRING_MAX];
		CHECK(PlatformIdentity::deriveIdentifiers(machineID, uuid, serial), "derivation succeeds");
		CHECK(std::memcmp(uuid, expectedUUID, 16) == 0, "UUID matches the independently computed HMAC-SHA256");
		CHECK((uuid[6] >> 4) == 4 && (uuid[8] >> 6) == 2, "UUID is RFC 4122 version 4");
		CHECK(std::strcmp(serial, expectedSerial) == 0, "serial is DARLING- plus bytes 16-19 of the HMAC");
		CHECK(std::memcmp(uuid, machineID, 16) != 0, "UUID is not the raw machine ID");
	}

	// defaults
	{
		PlatformIdentity identity(machineID);
		auto current = identity.current();
		CHECK(current.version == DSERVER_PLATFORM_IDENTITY_VERSION && current.size == sizeof(current), "defaults: version and size filled in");
		CHECK(current.generation == 0 && current.present == 0, "defaults: generation 0, nothing present");
#if __x86_64__ || __i386__
		CHECK(std::strcmp(current.model, "MacBookPro16,1") == 0, "defaults: model MacBookPro16,1");
		CHECK(std::strcmp(current.product_name, "MacBookPro16,1") == 0, "defaults: product name MacBookPro16,1");
		CHECK(std::strcmp(current.board_id, "Mac-E1008331FDC96864") == 0, "defaults: board ID of MacBookPro16,1");
#endif
		CHECK(std::memcmp(current.platform_uuid, expectedUUID, 16) == 0, "defaults: derived UUID");
		CHECK(std::strcmp(current.serial_number, expectedSerial) == 0, "defaults: derived serial");
		CHECK(current.cpu_brand_string[0] == 0 && current.memory_size == 0, "defaults: brand string and memory size left to the host");
		dserver_platform_identity_t zero;
		std::memset(&zero, 0, sizeof(zero));
		CHECK(std::memcmp(current.rom, zero.rom, sizeof(zero.rom)) == 0 && std::memcmp(current.system_id, zero.system_id, 16) == 0 &&
			std::memcmp(current.provisioning_udid, zero.provisioning_udid, 16) == 0 && current.mlb_serial_number[0] == 0,
			"defaults: ROM, MLB serial, system ID and provisioning UDID not synthesized");
	}

	// no machine ID
	{
		PlatformIdentity identity(nullptr);
		auto current = identity.current();
		uint8_t nil[16] = {};
		CHECK(std::memcmp(current.platform_uuid, nil, 16) == 0 && current.serial_number[0] == 0, "no machine ID: no UUID, no serial");
		CHECK(current.model[0] != 0, "no machine ID: model still set");
	}

	// a complete push
	{
		PlatformIdentity identity(machineID);
		auto pushed = fullPush();
		CHECK(identity.apply(pushed) == 0, "full push accepted");
		auto current = identity.current();
		CHECK(current.generation == 1 && current.present == DSERVER_PLATFORM_IDENTITY_HAS_ALL, "full push: generation 1, everything present");
		auto expected = pushed;
		expected.generation = 1;
		CHECK(sameIdentity(current, expected), "full push: every value in effect");
	}

	// an empty push keeps the defaults and counts
	{
		PlatformIdentity identity(machineID);
		auto defaults = identity.current();
		CHECK(identity.apply(emptyPush()) == 0 && identity.current().generation == 1, "empty push accepted");
		auto current = identity.current();
		current.generation = 0;
		CHECK(sameIdentity(current, defaults), "empty push: defaults in effect");
	}

	// a partial push falls back to the defaults for the rest, also after a full push
	{
		PlatformIdentity identity(machineID);
		identity.apply(fullPush());
		auto pushed = emptyPush();
		pushed.present = DSERVER_PLATFORM_IDENTITY_HAS_MODEL;
		std::strcpy(pushed.model, "iMac20,1");
		bool notified = false;
		CHECK(identity.apply(pushed, [&](const dserver_platform_identity_t& applied) { notified = applied.generation == 2; }) == 0 && notified, "partial push accepted and passed on");
		auto current = identity.current();
		CHECK(std::strcmp(current.model, "iMac20,1") == 0 && std::memcmp(current.platform_uuid, expectedUUID, 16) == 0 &&
			std::strcmp(current.serial_number, expectedSerial) == 0 && current.memory_size == 0 && current.rom[0] == 0,
			"partial push: pushed model, defaults for the rest");
	}

	// the provisioning UDID must be the platform UUID in effect
	{
		PlatformIdentity identity(machineID);
		auto pushed = emptyPush();
		pushed.present = DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID;
		std::memcpy(pushed.provisioning_udid, expectedUUID, 16);
		CHECK(identity.apply(pushed) == 0, "provisioning UDID equal to the derived UUID accepted");
		auto wrong = fullPush();
		wrong.provisioning_udid[0] ^= 1;
		checkRejected(wrong, "provisioning UDID different from the pushed UUID rejected");
		std::memcpy(pushed.provisioning_udid, pushedUUID, 16);
		checkRejected(pushed, "provisioning UDID different from the derived UUID rejected");
	}

	// every kind of malformed push is rejected
	{
		auto p = fullPush();
		p.version = 2;
		checkRejected(p, "wrong version rejected");
		p = fullPush();
		p.size -= 1;
		checkRejected(p, "wrong size rejected");
		p = fullPush();
		p.present |= 1u << 11;
		checkRejected(p, "unknown present bit rejected");
		p = fullPush();
		p.generation = 1;
		checkRejected(p, "nonzero generation rejected");
		p = fullPush();
		p.reserved = 1;
		checkRejected(p, "nonzero reserved rejected");
		p = fullPush();
		p.rom_reserved[1] = 1;
		checkRejected(p, "nonzero rom_reserved rejected");

		p = fullPush();
		std::memset(p.model, 'A', sizeof(p.model));
		checkRejected(p, "model without a NUL inside the field rejected");
		p = fullPush();
		std::memset(p.model, 0, sizeof(p.model));
		checkRejected(p, "empty model rejected");
		p = fullPush();
		p.board_id[3] = '\n';
		checkRejected(p, "control character in board ID rejected");
		p = fullPush();
		p.serial_number[0] = (char)0xc3;
		checkRejected(p, "non-ASCII serial rejected");
		p = fullPush();
		std::memset(p.platform_uuid, 0, 16);
		std::memset(p.provisioning_udid, 0, 16);
		p.present &= ~DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID;
		checkRejected(p, "nil platform UUID rejected");
		p = fullPush();
		std::memset(p.system_id, 0, 16);
		checkRejected(p, "all-zero system ID rejected");
		p = fullPush();
		std::memset(p.rom, 0, 6);
		checkRejected(p, "all-zero ROM rejected");
		p = fullPush();
		p.memory_size = 0;
		checkRejected(p, "zero memory size rejected");

		// values without their present bit
		p = fullPush();
		p.present &= ~DSERVER_PLATFORM_IDENTITY_HAS_CPU_BRAND_STRING;
		checkRejected(p, "brand string without its present bit rejected");
		p = fullPush();
		p.present &= ~DSERVER_PLATFORM_IDENTITY_HAS_MEMORY_SIZE;
		checkRejected(p, "memory size without its present bit rejected");
		p = fullPush();
		p.present &= ~DSERVER_PLATFORM_IDENTITY_HAS_ROM;
		checkRejected(p, "ROM without its present bit rejected");
		p = emptyPush();
		p.model[sizeof(p.model) - 1] = 'x';
		checkRejected(p, "stray byte in an absent string rejected");
	}

	// the longest string fits, and bytes after its NUL are dropped
	{
		PlatformIdentity identity(machineID);
		auto p = emptyPush();
		p.present = DSERVER_PLATFORM_IDENTITY_HAS_MODEL;
		std::memset(p.model, 'M', sizeof(p.model) - 1);
		CHECK(identity.apply(p) == 0 && std::strlen(identity.current().model) == sizeof(p.model) - 1, "longest model accepted");
		std::memset(p.model, 0, sizeof(p.model));
		std::strcpy(p.model, "Mac1,1");
		p.model[40] = 'Z';
		CHECK(identity.apply(p) == 0 && identity.current().model[40] == 0, "bytes after the NUL are not kept");
	}

	std::printf("%s\n", fails ? "FAILED" : "ALL PASSED");
	return fails ? 1 : 0;
}
