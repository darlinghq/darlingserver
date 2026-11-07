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

#include <darlingserver/platform-identity.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

static_assert(offsetof(dserver_platform_identity_t, generation) == 16, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_platform_identity_t, memory_size) == 24, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_platform_identity_t, platform_uuid) == 32, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_platform_identity_t, rom) == 80, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_platform_identity_t, model) == 88, "the layout must not depend on the architecture");
static_assert(sizeof(dserver_platform_identity_t) == 88 + 6 * DSERVER_PLATFORM_IDENTITY_STRING_MAX, "the layout must not depend on the architecture");

// the application ID that machine-id(5) asks every user of the machine ID to hash it with,
// so that the value we hand out cannot be correlated with the raw machine ID or with other
// applications' IDs. it was generated randomly once and must never change: changing it
// changes the platform UUID and serial number of every existing prefix.
static const uint8_t darlingApplicationID[16] = {
	0xea, 0xa5, 0x77, 0xe8, 0x50, 0x5a, 0x4d, 0x80, 0xbd, 0xfc, 0x83, 0x0d, 0x3e, 0xda, 0x32, 0x18,
};

#if __x86_64__ || __i386__
// a 16-inch MacBook Pro (2019), one of the Intel models macOS 26 supports
static const char defaultModel[] = "MacBookPro16,1";
static const char defaultProductName[] = "MacBookPro16,1";
static const char defaultBoardID[] = "Mac-E1008331FDC96864";
#elif __aarch64__
// a MacBook Air (M2, 2022); Apple silicon Macs have no "Mac-" board ID and use a marketing
// name as the product name, which is not synthesized
static const char defaultModel[] = "Mac14,2";
static const char defaultProductName[] = "";
static const char defaultBoardID[] = "";
#else
	#error Unknown architecture
#endif

static const char serialPrefix[] = "DARLING-";

static bool allZero(const void* bytes, size_t length) {
	const uint8_t* p = static_cast<const uint8_t*>(bytes);
	for (size_t i = 0; i < length; ++i) {
		if (p[i] != 0) {
			return false;
		}
	}
	return true;
};

template<size_t N>
static void copyString(char (&to)[N], const char* from) {
	memset(to, 0, N);
	strncpy(to, from, N - 1);
};

// a pushed string: terminated inside its field, not empty, printable ASCII
template<size_t N>
static bool validString(const char (&field)[N]) {
	const void* nul = memchr(field, '\0', N);
	if (!nul) {
		return false;
	}
	size_t length = static_cast<const char*>(nul) - field;
	if (length == 0) {
		return false;
	}
	for (size_t i = 0; i < length; ++i) {
		unsigned char c = field[i];
		if (c < 0x20 || c > 0x7e) {
			return false;
		}
	}
	return true;
};

static int hexValue(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return 10 + (c - 'a');
	} else if (c >= 'A' && c <= 'F') {
		return 10 + (c - 'A');
	}
	return -1;
};

bool DarlingServer::PlatformIdentity::parseMachineID(const char* text, size_t length, uint8_t machineID[machineIDSize]) {
	if (length == machineIDSize * 2 + 1 && text[machineIDSize * 2] == '\n') {
		--length;
	}
	if (length != machineIDSize * 2) {
		return false;
	}

	uint8_t parsed[machineIDSize];
	for (size_t i = 0; i < machineIDSize; ++i) {
		int high = hexValue(text[i * 2]);
		int low = hexValue(text[i * 2 + 1]);
		if (high < 0 || low < 0) {
			return false;
		}
		parsed[i] = (high << 4) | low;
	}

	if (allZero(parsed, sizeof(parsed))) {
		return false;
	}

	memcpy(machineID, parsed, sizeof(parsed));
	OPENSSL_cleanse(parsed, sizeof(parsed));
	return true;
};

bool DarlingServer::PlatformIdentity::readMachineID(const char* path, uint8_t machineID[machineIDSize]) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}

	// one byte more than a valid file holds, so that a longer file is noticed
	char buffer[machineIDSize * 2 + 2];
	size_t length = 0;
	while (length < sizeof(buffer)) {
		ssize_t count = read(fd, buffer + length, sizeof(buffer) - length);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			break;
		}
		length += count;
	}
	close(fd);

	bool ok = parseMachineID(buffer, length, machineID);
	OPENSSL_cleanse(buffer, sizeof(buffer));
	return ok;
};

bool DarlingServer::PlatformIdentity::deriveIdentifiers(const uint8_t machineID[machineIDSize], uint8_t uuid[uuidSize], char serial[DSERVER_PLATFORM_IDENTITY_STRING_MAX]) {
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digestLength = 0;

	if (!HMAC(EVP_sha256(), machineID, machineIDSize, darlingApplicationID, sizeof(darlingApplicationID), digest, &digestLength) || digestLength < uuidSize + 4) {
		OPENSSL_cleanse(digest, sizeof(digest));
		return false;
	}

	memcpy(uuid, digest, uuidSize);
	uuid[6] = (uuid[6] & 0x0f) | 0x40; // RFC 4122 version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant

	memset(serial, 0, DSERVER_PLATFORM_IDENTITY_STRING_MAX);
	snprintf(serial, DSERVER_PLATFORM_IDENTITY_STRING_MAX, "%s%02X%02X%02X%02X", serialPrefix,
		digest[uuidSize], digest[uuidSize + 1], digest[uuidSize + 2], digest[uuidSize + 3]);

	OPENSSL_cleanse(digest, sizeof(digest));
	return true;
};

DarlingServer::PlatformIdentity::PlatformIdentity(const uint8_t* machineID) {
	memset(&_defaults, 0, sizeof(_defaults));
	_defaults.version = DSERVER_PLATFORM_IDENTITY_VERSION;
	_defaults.size = sizeof(_defaults);
	copyString(_defaults.model, defaultModel);
	copyString(_defaults.product_name, defaultProductName);
	copyString(_defaults.board_id, defaultBoardID);

	if (machineID && !deriveIdentifiers(machineID, _defaults.platform_uuid, _defaults.serial_number)) {
		memset(_defaults.platform_uuid, 0, sizeof(_defaults.platform_uuid));
		memset(_defaults.serial_number, 0, sizeof(_defaults.serial_number));
	}

	_identity = _defaults;
};

DarlingServer::PlatformIdentity& DarlingServer::PlatformIdentity::sharedInstance() {
	static PlatformIdentity* instance = []() {
		uint8_t machineID[machineIDSize];
		// /var/lib/dbus/machine-id is the older location that machine-id(5) still mentions
		bool known = readMachineID("/etc/machine-id", machineID) || readMachineID("/var/lib/dbus/machine-id", machineID);
		auto identity = new PlatformIdentity(known ? machineID : nullptr);
		OPENSSL_cleanse(machineID, sizeof(machineID));
		return identity;
	}();
	return *instance;
};

int DarlingServer::PlatformIdentity::validate(const dserver_platform_identity_t& pushed) const {
	if (pushed.version != DSERVER_PLATFORM_IDENTITY_VERSION || pushed.size != sizeof(dserver_platform_identity_t)) {
		return -EINVAL;
	}

	if ((pushed.present & ~DSERVER_PLATFORM_IDENTITY_HAS_ALL) != 0 || pushed.generation != 0 || pushed.reserved != 0 || !allZero(pushed.rom_reserved, sizeof(pushed.rom_reserved))) {
		return -EINVAL;
	}

	// a value that was not pushed must be zero, so that a daemon bug that fills in a value
	// but forgets its `present` bit does not go unnoticed
	auto check = [&](uint32_t bit, const void* field, size_t size, bool valid) {
		return (pushed.present & bit) ? valid : allZero(field, size);
	};

	#define CHECK_STRING(bit, field) \
		check(bit, pushed.field, sizeof(pushed.field), validString(pushed.field))
	#define CHECK_BYTES(bit, field) \
		check(bit, pushed.field, sizeof(pushed.field), !allZero(pushed.field, sizeof(pushed.field)))

	bool ok =
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_MODEL, model) &&
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_PRODUCT_NAME, product_name) &&
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_BOARD_ID, board_id) &&
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_SERIAL_NUMBER, serial_number) &&
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_MLB_SERIAL_NUMBER, mlb_serial_number) &&
		CHECK_STRING(DSERVER_PLATFORM_IDENTITY_HAS_CPU_BRAND_STRING, cpu_brand_string) &&
		CHECK_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_PLATFORM_UUID, platform_uuid) &&
		CHECK_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_SYSTEM_ID, system_id) &&
		CHECK_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID, provisioning_udid) &&
		CHECK_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_ROM, rom) &&
		check(DSERVER_PLATFORM_IDENTITY_HAS_MEMORY_SIZE, &pushed.memory_size, sizeof(pushed.memory_size), pushed.memory_size != 0);

	#undef CHECK_STRING
	#undef CHECK_BYTES

	if (!ok) {
		return -EINVAL;
	}

	// the provisioning UDID is the platform UUID; it may only be configured to the one in effect
	if (pushed.present & DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID) {
		const uint8_t* uuid = (pushed.present & DSERVER_PLATFORM_IDENTITY_HAS_PLATFORM_UUID) ? pushed.platform_uuid : _defaults.platform_uuid;
		if (memcmp(pushed.provisioning_udid, uuid, uuidSize) != 0) {
			return -EINVAL;
		}
	}

	return 0;
};

int DarlingServer::PlatformIdentity::apply(const dserver_platform_identity_t& pushed, const std::function<void(const dserver_platform_identity_t&)>& onApply) {
	int code = validate(pushed);
	if (code != 0) {
		return code;
	}

	// build the new identity from the defaults and the values that were pushed
	dserver_platform_identity_t next = _defaults;
	next.present = pushed.present;

	#define TAKE_STRING(bit, field) \
		if (pushed.present & bit) { copyString(next.field, pushed.field); }
	#define TAKE_BYTES(bit, field) \
		if (pushed.present & bit) { memcpy(next.field, pushed.field, sizeof(next.field)); }

	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_MODEL, model);
	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_PRODUCT_NAME, product_name);
	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_BOARD_ID, board_id);
	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_SERIAL_NUMBER, serial_number);
	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_MLB_SERIAL_NUMBER, mlb_serial_number);
	TAKE_STRING(DSERVER_PLATFORM_IDENTITY_HAS_CPU_BRAND_STRING, cpu_brand_string);
	TAKE_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_PLATFORM_UUID, platform_uuid);
	TAKE_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_SYSTEM_ID, system_id);
	TAKE_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID, provisioning_udid);
	TAKE_BYTES(DSERVER_PLATFORM_IDENTITY_HAS_ROM, rom);
	if (pushed.present & DSERVER_PLATFORM_IDENTITY_HAS_MEMORY_SIZE) {
		next.memory_size = pushed.memory_size;
	}

	#undef TAKE_STRING
	#undef TAKE_BYTES

	std::unique_lock lock(_mutex);

	next.generation = _identity.generation + 1;
	_identity = next;

	if (onApply) {
		onApply(_identity);
	}

	return 0;
};

dserver_platform_identity_t DarlingServer::PlatformIdentity::current() const {
	std::unique_lock lock(_mutex);
	return _identity;
};
