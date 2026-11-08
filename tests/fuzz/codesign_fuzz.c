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

// libFuzzer target for the code signature parser: treats the input as a file, looks up every image
// in it the way darlingserver does (the fat table, then each image), parses each signature, checks
// the code pages and looks up keys in the embedded entitlements. Besides the sanitizers, it checks
// that everything the parser hands back lies inside the input. See tests/run-fuzz.sh.
#include <darlingserver/dc_codesign.h>
#include <darlingserver/dc_entitlements.h>

#include <stdbool.h>
#include <string.h>

static bool inside(const uint8_t* base, size_t size, const uint8_t* p, uint64_t length) {
	return p >= base && (uint64_t)(p - base) <= size && length <= size - (uint64_t)(p - base);
}

#define REQUIRE(c) do { if (!(c)) __builtin_trap(); } while (0)

static void check_image(const uint8_t* data, size_t size) {
	struct dc_cs_image image;
	char err[128];
	uint64_t needed = 0;

	// the two-step path with separate buffers, as darlingserver reads a file
	if (dc_cs_header_length(data, size, size, &needed, err, sizeof(err)) == 0) {
		REQUIRE(needed <= size);
	}

	int result = dc_cs_parse(data, size, &image, err, sizeof(err));
	REQUIRE(memchr(err, '\0', sizeof(err)) != NULL || result >= 0);
	if (result != 0) {
		return;
	}

	REQUIRE(image.signature_offset >= image.load_commands_end);
	REQUIRE(inside(data, size, data + image.signature_offset, image.signature_size));
	REQUIRE(image.codedirectory && image.codedirectory_count > 0 && image.codedirectory_count <= DC_CS_MAX_CODEDIRECTORIES);
	for (uint32_t i = 0; i < image.codedirectory_count; ++i) {
		REQUIRE(inside(data, size, image.codedirectories[i].data, image.codedirectories[i].length));
	}
	REQUIRE(image.code_limit <= image.signature_offset && image.code_limit >= image.load_commands_end);
	REQUIRE(strlen(image.identifier) < DC_CS_IDENTIFIER_MAX && strlen(image.team_id) < DC_CS_TEAM_ID_MAX);
	REQUIRE(!image.requirements || inside(data, size, image.requirements, image.requirements_length));
	REQUIRE(!image.entitlements || inside(data, size, image.entitlements, image.entitlements_length));
	REQUIRE(!image.der_entitlements || inside(data, size, image.der_entitlements, image.der_entitlements_length));
	REQUIRE(!image.cms || inside(data, size, image.cms, image.cms_length));

	uint32_t first_bad = 0;
	dc_cs_verify_pages(&image, data, size, &first_bad, err, sizeof(err));

	if (image.entitlements && image.entitlements_length > 8) {
		static const char* const keys[] = { "com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation" };
		enum dc_cs_entitlement_value values[2];
		dc_cs_entitlements_lookup(image.entitlements + 8, image.entitlements_length - 8, keys, 2, values);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	char err[128];
	uint64_t image_size = 0;

	if (size < 8) {
		check_image(data, size);
		return 0;
	}

	// a thin file
	if (dc_cs_image_at(data, size, size, 0, &image_size, err, sizeof(err)) == 0) {
		REQUIRE(image_size == size);
		check_image(data, size);
	}

	// every slice a fat table names (big-endian offsets; 32- and 64-bit tables)
	uint32_t magic = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
	uint32_t count = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | data[7];
	size_t entry_size = (magic == 0xcafebabfu) ? 32 : 20;
	for (uint32_t i = 0; i < count && i < DC_CS_FAT_MAX_ARCHS; ++i) {
		size_t position = 8 + i * entry_size + 8;
		uint64_t offset = 0;
		if (position + (entry_size == 32 ? 8 : 4) > size) {
			break;
		}
		for (size_t j = 0; j < (entry_size == 32 ? 8 : 4); ++j) {
			offset = (offset << 8) | data[position + j];
		}
		if (dc_cs_image_at(data, size, size, offset, &image_size, err, sizeof(err)) == 0) {
			REQUIRE(offset <= size && image_size <= size - offset);
			check_image(data + offset, (size_t)image_size);
		}
	}

	return 0;
}
