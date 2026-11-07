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

// The code signature parser (src/codesign, compiled unchanged) against binaries signed by
// `codesign` on macOS (tests/fixtures/codesign; the expected values are its `codesign -dvvv`
// output, in codesign-dvvv.txt there), and against malformed variants of them.
// Usage: codesign_test <fixture directory>
#include <darlingserver/dc_codesign.h>
#include <darlingserver/dc_entitlements.h>
#include <kern/cs_blobs.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c, what) do { int ok_ = (c); printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// <mach/machine.h>: CPU_ARCH_ABI64 | CPU_TYPE_X86 and CPU_ARCH_ABI64 | CPU_TYPE_ARM
#define TEST_CPU_TYPE_X86_64 0x01000007u
#define TEST_CPU_TYPE_ARM64  0x0100000cu

static const char* fixture_dir;

struct buffer {
	uint8_t* data;
	size_t size;
};

static struct buffer load(const char* name) {
	char path[4096];
	struct buffer result = { NULL, 0 };
	snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
	FILE* file = fopen(path, "rb");
	if (!file) {
		fprintf(stderr, "cannot open %s\n", path);
		exit(2);
	}
	fseek(file, 0, SEEK_END);
	result.size = (size_t)ftell(file);
	fseek(file, 0, SEEK_SET);
	result.data = malloc(result.size);
	if (!result.data || fread(result.data, 1, result.size, file) != result.size) {
		fprintf(stderr, "cannot read %s\n", path);
		exit(2);
	}
	fclose(file);
	return result;
}

static struct buffer copy(struct buffer source) {
	struct buffer result = { malloc(source.size), source.size };
	memcpy(result.data, source.data, source.size);
	return result;
}

static void hex(const uint8_t* bytes, size_t length, char* out) {
	for (size_t i = 0; i < length; ++i) {
		sprintf(out + 2 * i, "%02x", bytes[i]);
	}
	out[2 * length] = '\0';
}

static bool cdhash_is(const struct dc_cs_image* image, const char* expected) {
	char text[2 * DC_CS_CDHASH_LEN + 1];
	hex(image->cdhash, DC_CS_CDHASH_LEN, text);
	if (strcmp(text, expected) != 0) {
		printf("  cdhash %s, expected %s\n", text, expected);
		return false;
	}
	return true;
}

static uint32_t be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t* p, uint32_t value) {
	p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value;
}

static void put_le32(uint8_t* p, uint32_t value) {
	p[0] = value; p[1] = value >> 8; p[2] = value >> 16; p[3] = value >> 24;
}

static uint32_t le32(const uint8_t* p) {
	return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// parses `data` and checks the result against `expected` (0, DC_CS_UNSIGNED or -1)
static int parse(const struct buffer* data, struct dc_cs_image* image, const char* what) {
	char err[256] = "";
	int result = dc_cs_parse(data->data, data->size, image, err, sizeof(err));
	if (result < 0) {
		printf("  %s: %s\n", what, err);
	}
	return result;
}

static bool parse_fails(struct buffer data, const char* what) {
	struct dc_cs_image image;
	char err[256] = "";
	int result = dc_cs_parse(data.data, data.size, &image, err, sizeof(err));
	if (result >= 0) {
		printf("  %s: unexpectedly parsed (%d)\n", what, result);
	} else if (err[0] == '\0') {
		printf("  %s: no reason given\n", what);
		result = 0;
	} else {
		printf("  %s: %s\n", what, err);
	}
	free(data.data);
	return result < 0;
}

static bool pages_verify(const struct dc_cs_image* image, const struct buffer* data, uint32_t* first_bad) {
	char err[256] = "";
	return dc_cs_verify_pages(image, data->data, data->size, first_bad, err, sizeof(err)) == 0;
}

// the offset in the file of the given blob of an image parsed from `data`
static size_t blob_offset(const struct dc_cs_image* image, uint32_t type) {
	for (uint32_t i = 0; i < image->blob_count; ++i) {
		if (image->blobs[i].type == type) {
			return (size_t)image->signature_offset + image->blobs[i].offset;
		}
	}
	return 0;
}

// the offset in the file of the SuperBlob index entry for the given blob type
static size_t index_entry_offset(const struct dc_cs_image* image, uint32_t type) {
	for (uint32_t i = 0; i < image->blob_count; ++i) {
		if (image->blobs[i].type == type) {
			return (size_t)image->signature_offset + 12 + 8 * i;
		}
	}
	return 0;
}

// the offset in the file of the first load command `command`
static size_t load_command_offset(const struct buffer* data, uint32_t command) {
	uint32_t count = le32(data->data + 16);
	size_t position = 32;
	for (uint32_t i = 0; i < count; ++i) {
		if (le32(data->data + position) == command) {
			return position;
		}
		position += le32(data->data + position + 4);
	}
	return 0;
}

static void test_valid_fixtures(void) {
	struct dc_cs_image image;
	uint32_t first_bad = 0;

	{
		struct buffer data = load("linker-signed");
		CHECK(parse(&data, &image, "linker-signed") == 0, "linker-signed: parses");
		CHECK(strcmp(image.identifier, "linker-signed") == 0 && image.team_id[0] == '\0', "linker-signed: identifier, no team ID");
		CHECK(image.cd_version == 0x20400 && image.cd_flags == (CS_ADHOC | CS_LINKER_SIGNED), "linker-signed: CodeDirectory v=20400 flags=0x20002(adhoc,linker-signed)");
		CHECK(image.hash_type == CS_HASHTYPE_SHA256 && image.hash_size == 32, "linker-signed: hash type sha256 size 32");
		CHECK(image.code_slot_count == 5 && image.special_slot_count == 0, "linker-signed: hashes=5+0");
		CHECK(cdhash_is(&image, "1e010f88a0f10df1da428fb53fad98a1637453ba"), "linker-signed: CDHash");
		CHECK(image.codedirectory_count == 1 && !image.requirements && !image.entitlements && !image.cms, "linker-signed: no requirements, entitlements or CMS blob");
		CHECK(image.cputype == TEST_CPU_TYPE_ARM64 && image.is_64, "linker-signed: arm64");
		CHECK(image.exec_seg_limit > 0 && (image.exec_seg_flags & CS_EXECSEG_MAIN_BINARY), "linker-signed: executable segment of a main binary");
		CHECK(pages_verify(&image, &data, &first_bad), "linker-signed: every code page matches");
		free(data.data);
	}

	{
		struct buffer data = load("adhoc");
		CHECK(parse(&data, &image, "adhoc") == 0, "adhoc: parses");
		CHECK(strcmp(image.identifier, "org.darlinghq.test.adhoc") == 0, "adhoc: identifier");
		CHECK(image.cd_version == 0x20400 && image.cd_flags == CS_ADHOC, "adhoc: CodeDirectory v=20400 flags=0x2(adhoc)");
		CHECK(image.code_slot_count == 2 && image.special_slot_count == 2 && image.page_size_log2 == 14, "adhoc: hashes=2+2, 16 KiB pages");
		CHECK(cdhash_is(&image, "c3e41403df5753a157520767cbf90e56d9ffa33f"), "adhoc: CDHash");
		CHECK(image.requirements && image.requirements_length == 12, "adhoc: internal requirements count=0 size=12");
		CHECK(image.cms && image.cms_length == 0, "adhoc: empty CMS wrapper (Signature=adhoc)");
		CHECK(!image.info_plist_bound && !image.resources_bound, "adhoc: Info.plist and resources not bound");
		CHECK(pages_verify(&image, &data, &first_bad), "adhoc: every code page matches");
		free(data.data);
	}

	{
		struct buffer data = load("adhoc-runtime-ent");
		CHECK(parse(&data, &image, "adhoc-runtime-ent") == 0, "adhoc-runtime-ent: parses");
		CHECK(strcmp(image.identifier, "org.darlinghq.test.runtime") == 0, "adhoc-runtime-ent: identifier");
		CHECK(image.cd_version == 0x20500 && image.cd_flags == (CS_ADHOC | CS_RUNTIME), "adhoc-runtime-ent: CodeDirectory v=20500 flags=0x10002(adhoc,runtime)");
		CHECK(image.runtime_version == 0x1b0000, "adhoc-runtime-ent: Runtime Version=27.0.0");
		CHECK(image.code_slot_count == 2 && image.special_slot_count == 7, "adhoc-runtime-ent: hashes=2+7");
		CHECK(image.hash_type == CS_HASHTYPE_SHA256 && cdhash_is(&image, "67316e6b715fa9eb830be17fe5e363126d0441db"), "adhoc-runtime-ent: the sha256 CodeDirectory is chosen (CDHash)");
		CHECK(image.codedirectory_count == 2, "adhoc-runtime-ent: Hash choices=sha1,sha256");
		{
			char text[2 * DC_CS_HASH_MAX_SIZE + 1] = "";
			for (uint32_t i = 0; i < image.codedirectory_count; ++i) {
				if (image.codedirectories[i].hash_type == CS_HASHTYPE_SHA1) {
					hex(image.codedirectories[i].digest, image.codedirectories[i].digest_length, text);
				}
			}
			CHECK(strcmp(text, "49c5d77b0fe0fa19ada939afcae5877e5251cfe6") == 0, "adhoc-runtime-ent: CandidateCDHashFull sha1");
		}
		{
			char text[2 * DC_CS_HASH_MAX_SIZE + 1];
			hex(image.codedirectory->digest, image.codedirectory->digest_length, text);
			CHECK(strcmp(text, "67316e6b715fa9eb830be17fe5e363126d0441dbcb965cd7a16fe81ed14eb547") == 0, "adhoc-runtime-ent: CandidateCDHashFull sha256");
		}
		CHECK(image.entitlements && be32(image.entitlements) == CSMAGIC_EMBEDDED_ENTITLEMENTS, "adhoc-runtime-ent: entitlements blob");
		CHECK(image.der_entitlements && be32(image.der_entitlements) == 0xfade7172u, "adhoc-runtime-ent: DER entitlements blob");
		CHECK(pages_verify(&image, &data, &first_bad), "adhoc-runtime-ent: every code page matches");

		static const char* const keys[] = {
			"com.apple.security.get-task-allow",
			"com.apple.security.cs.disable-library-validation",
			"org.darlinghq.test.string",
			"com.apple.security.cs.allow-jit",
		};
		enum dc_cs_entitlement_value values[4];
		int result = dc_cs_entitlements_lookup(image.entitlements + 8, image.entitlements_length - 8, keys, 4, values);
		CHECK(result == 0, "adhoc-runtime-ent: the entitlements plist is well-formed");
		CHECK(values[0] == DC_CS_ENTITLEMENT_TRUE && values[1] == DC_CS_ENTITLEMENT_FALSE && values[2] == DC_CS_ENTITLEMENT_OTHER && values[3] == DC_CS_ENTITLEMENT_ABSENT,
			"adhoc-runtime-ent: get-task-allow true, disable-library-validation false, a string, an absent key");
		free(data.data);
	}

	{
		struct buffer data = load("cms-signed");
		CHECK(parse(&data, &image, "cms-signed") == 0, "cms-signed: parses");
		CHECK(image.cd_flags == 0 && strcmp(image.identifier, "org.darlinghq.test.cms") == 0, "cms-signed: flags=0x0(none), identifier");
		CHECK(cdhash_is(&image, "624f2b1e6c289dd7eae03f89ef5c22b6fa4dd077"), "cms-signed: CDHash");
		CHECK(image.requirements_length == 100, "cms-signed: internal requirements count=1 size=100");
		CHECK(image.cms && image.cms_length > 0 && image.cms[0] == 0x30, "cms-signed: CMS blob holds a DER SEQUENCE");
		CHECK(pages_verify(&image, &data, &first_bad), "cms-signed: every code page matches");
		free(data.data);
	}

	{
		struct buffer data = load("cms-dual");
		CHECK(parse(&data, &image, "cms-dual") == 0, "cms-dual: parses");
		CHECK(image.cd_flags == CS_RUNTIME && image.codedirectory_count == 2, "cms-dual: flags=0x10000(runtime), two CodeDirectories");
		CHECK(cdhash_is(&image, "ab4845f2918045f80e0cf97f39d8e648536d489b"), "cms-dual: CDHash");
		CHECK(image.requirements_length == 104 && image.entitlements && image.cms_length > 0, "cms-dual: requirements size=104, entitlements, CMS");
		CHECK(pages_verify(&image, &data, &first_bad), "cms-dual: every code page matches");
		free(data.data);
	}

	{
		struct buffer data = load("unsigned");
		CHECK(parse(&data, &image, "unsigned") == DC_CS_UNSIGNED, "unsigned: reported as not signed");
		free(data.data);
	}
}

static void test_fat(void) {
	struct buffer data = load("fat-adhoc");
	char err[256];
	uint32_t count = be32(data.data + 4);
	bool seen_x86_64 = false, seen_arm64 = false;

	for (uint32_t i = 0; i < count; ++i) {
		uint32_t offset = be32(data.data + 8 + 20 * i + 8);
		uint64_t size = 0;
		struct dc_cs_image image;
		uint32_t first_bad = 0;

		if (dc_cs_image_at(data.data, data.size, data.size, offset, &size, err, sizeof(err)) != 0) {
			printf("  %s\n", err);
			continue;
		}
		struct buffer slice = { data.data + offset, (size_t)size };
		if (parse(&slice, &image, "fat slice") != 0) {
			continue;
		}
		if (image.cputype == TEST_CPU_TYPE_X86_64) {
			seen_x86_64 = cdhash_is(&image, "1744200c4dabb96a8f18824726f3468dbfb0c16c") && pages_verify(&image, &slice, &first_bad);
		} else if (image.cputype == TEST_CPU_TYPE_ARM64) {
			seen_arm64 = cdhash_is(&image, "878f5e5d73364fd8b9787492260174038a011f6a") && pages_verify(&image, &slice, &first_bad);
		}
	}
	CHECK(seen_x86_64, "fat-adhoc: the x86_64 slice has its own CDHash and verifies");
	CHECK(seen_arm64, "fat-adhoc: the arm64 slice has its own CDHash and verifies");

	uint64_t size = 0;
	CHECK(dc_cs_image_at(data.data, data.size, data.size, 0, &size, err, sizeof(err)) != 0, "fat: offset 0 is not a slice");
	CHECK(dc_cs_image_at(data.data, data.size, data.size, be32(data.data + 16) + 1, &size, err, sizeof(err)) != 0, "fat: an offset inside a slice is not a slice");
	CHECK(dc_cs_image_at(data.data, 8 + 20, data.size, be32(data.data + 16), &size, err, sizeof(err)) != 0, "fat: arch table not entirely in the buffer");

	{
		struct buffer bad = copy(data);
		put_be32(bad.data + 4, 0);
		CHECK(dc_cs_image_at(bad.data, bad.size, bad.size, 0, &size, err, sizeof(err)) != 0, "fat: no slices");
		put_be32(bad.data + 4, DC_CS_FAT_MAX_ARCHS + 1);
		CHECK(dc_cs_image_at(bad.data, bad.size, bad.size, 0, &size, err, sizeof(err)) != 0, "fat: too many slices");
		free(bad.data);
	}
	{
		struct buffer bad = copy(data);
		uint32_t first_offset = be32(bad.data + 16);
		// make the second slice start inside the first one
		put_be32(bad.data + 28 + 8, first_offset + 16);
		CHECK(dc_cs_image_at(bad.data, bad.size, bad.size, first_offset, &size, err, sizeof(err)) != 0, "fat: overlapping slices");
		free(bad.data);
	}
	{
		struct buffer bad = copy(data);
		put_be32(bad.data + 8 + 12, 0xfffffff0u);
		CHECK(dc_cs_image_at(bad.data, bad.size, bad.size, be32(bad.data + 16), &size, err, sizeof(err)) != 0, "fat: slice runs past the end of the file");
		free(bad.data);
	}
	{
		struct buffer bad = copy(data);
		put_be32(bad.data + 8 + 8, 8);
		CHECK(dc_cs_image_at(bad.data, bad.size, bad.size, 8, &size, err, sizeof(err)) != 0, "fat: slice overlapping the arch table");
		free(bad.data);
	}
	{
		struct buffer thin = load("adhoc");
		CHECK(dc_cs_image_at(thin.data, thin.size, thin.size, 0, &size, err, sizeof(err)) == 0 && size == thin.size, "thin: the image is the whole file");
		CHECK(dc_cs_image_at(thin.data, thin.size, thin.size, 4096, &size, err, sizeof(err)) != 0, "thin: no image at a nonzero offset");
		free(thin.data);
	}

	free(data.data);
}

static void test_tampering(void) {
	struct buffer pristine = load("adhoc-runtime-ent");
	struct dc_cs_image image;
	uint32_t first_bad = 0;

	if (parse(&pristine, &image, "adhoc-runtime-ent") != 0) {
		CHECK(0, "tampering: fixture parses");
		return;
	}

	// a changed code page still parses but no longer verifies
	{
		struct buffer bad = copy(pristine);
		struct dc_cs_image tampered;
		size_t page = (size_t)1 << image.page_size_log2;
		bad.data[page + 5] ^= 0x01;
		CHECK(parse(&bad, &tampered, "page") == 0 && !pages_verify(&tampered, &bad, &first_bad) && first_bad == 1, "tampered code page: page 1 reported as not matching");
		uint64_t length = dc_cs_page_length(&tampered, 1);
		CHECK(dc_cs_verify_page(&tampered, 0, bad.data, (size_t)dc_cs_page_length(&tampered, 0)) == 0 && dc_cs_verify_page(&tampered, 1, bad.data + page, (size_t)length) != 0, "tampered code page: single-page checks agree");
		CHECK(dc_cs_verify_page(&tampered, 0, bad.data, page - 1) != 0 && dc_cs_verify_page(&tampered, tampered.code_slot_count, bad.data, page) != 0, "verify_page: wrong length or index rejected");
		free(bad.data);
	}

	// a changed load command is covered by page 0
	{
		struct buffer bad = copy(pristine);
		struct dc_cs_image tampered;
		size_t uuid = load_command_offset(&bad, 0x1b /* LC_UUID */);
		bad.data[uuid + 8] ^= 0x01;
		CHECK(uuid != 0 && parse(&bad, &tampered, "LC_UUID") == 0 && !pages_verify(&tampered, &bad, &first_bad) && first_bad == 0, "tampered load command: page 0 reported as not matching");
		free(bad.data);
	}

	{
		struct buffer bad = copy(pristine);
		bad.size = (size_t)image.signature_offset + image.signature_size - 1;
		CHECK(parse_fails(bad, "truncated"), "truncated signature rejected");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[image.signature_offset] ^= 0xff;
		CHECK(parse_fails(bad, "superblob magic"), "bad SuperBlob magic rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + image.signature_offset + 4, image.signature_size + 1);
		CHECK(parse_fails(bad, "superblob length"), "SuperBlob longer than the signature rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + image.signature_offset + 8, 0x10000000);
		CHECK(parse_fails(bad, "blob count"), "huge blob count rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + index_entry_offset(&image, CSSLOT_ENTITLEMENTS) + 4, image.superblob_length - 4);
		CHECK(parse_fails(bad, "blob offset"), "blob offset near the end of the SuperBlob rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + index_entry_offset(&image, CSSLOT_ENTITLEMENTS) + 4, 4);
		CHECK(parse_fails(bad, "blob offset in index"), "blob offset inside the index rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + blob_offset(&image, CSSLOT_ENTITLEMENTS) + 4, 0xffffff00u);
		CHECK(parse_fails(bad, "blob length"), "blob length past the SuperBlob rejected");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[blob_offset(&image, CSSLOT_ENTITLEMENTS) + 40] ^= 0x01;
		CHECK(parse_fails(bad, "entitlements"), "changed entitlements do not match their special slot");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[blob_offset(&image, 7) + 20] ^= 0x01;
		CHECK(parse_fails(bad, "der entitlements"), "changed DER entitlements do not match their special slot");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[blob_offset(&image, CSSLOT_REQUIREMENTS) + 9] ^= 0x01;
		CHECK(parse_fails(bad, "requirements"), "changed requirements do not match their special slot");
	}
	{
		// hiding the entitlements blob behind another slot type leaves its special slot set
		struct buffer bad = copy(pristine);
		put_be32(bad.data + index_entry_offset(&image, CSSLOT_ENTITLEMENTS), CSSLOT_IDENTIFICATIONSLOT);
		CHECK(parse_fails(bad, "hidden entitlements"), "special slot set without its blob rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + index_entry_offset(&image, CSSLOT_REQUIREMENTS), CSSLOT_ENTITLEMENTS);
		CHECK(parse_fails(bad, "duplicate type"), "two blobs of the same type rejected");
	}

	size_t cd = blob_offset(&image, CSSLOT_CODEDIRECTORY);
	{
		struct buffer bad = copy(pristine);
		bad.data[cd + offsetof(CS_CodeDirectory, hashType)] = 9;
		CHECK(parse_fails(bad, "hash type"), "unknown hash type rejected");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[cd + offsetof(CS_CodeDirectory, hashSize)] = 32;
		CHECK(parse_fails(bad, "hash size"), "hash size not matching the hash type rejected");
	}
	{
		struct buffer bad = copy(pristine);
		bad.data[cd + offsetof(CS_CodeDirectory, pageSize)] = 30;
		CHECK(parse_fails(bad, "page size"), "unsupported page size rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, nCodeSlots), 0x40000000);
		CHECK(parse_fails(bad, "code slots"), "code slot count not matching the code limit rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, nSpecialSlots), 0x10000000);
		CHECK(parse_fails(bad, "special slots"), "special slots before the CodeDirectory rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, hashOffset), 0xfffffff0u);
		CHECK(parse_fails(bad, "hash offset"), "hash offset past the CodeDirectory rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, identOffset), 0xfffffff0u);
		CHECK(parse_fails(bad, "identifier"), "identifier offset past the CodeDirectory rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, identOffset), 8);
		CHECK(parse_fails(bad, "identifier in header"), "identifier inside the CodeDirectory header rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, codeLimit), (uint32_t)image.signature_offset + 1);
		CHECK(parse_fails(bad, "code limit"), "code limit reaching into the signature rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, version), 0x30000);
		CHECK(parse_fails(bad, "version"), "unknown CodeDirectory major version rejected");
	}
	{
		struct buffer bad = copy(pristine);
		put_be32(bad.data + cd + offsetof(CS_CodeDirectory, spare2), 1);
		CHECK(parse_fails(bad, "spare2"), "nonzero spare2 rejected");
	}
	{
		// both CodeDirectories with the same hash type
		struct buffer bad = copy(pristine);
		size_t alternate = blob_offset(&image, CSSLOT_ALTERNATE_CODEDIRECTORIES);
		bad.data[alternate + offsetof(CS_CodeDirectory, hashType)] = bad.data[cd + offsetof(CS_CodeDirectory, hashType)];
		bad.data[alternate + offsetof(CS_CodeDirectory, hashSize)] = bad.data[cd + offsetof(CS_CodeDirectory, hashSize)];
		CHECK(parse_fails(bad, "duplicate hash type"), "two CodeDirectories with the same hash type rejected");
	}

	{
		size_t signature = load_command_offset(&pristine, 0x1d /* LC_CODE_SIGNATURE */);
		struct buffer bad = copy(pristine);
		put_le32(bad.data + signature + 12, 0xfffffff0u);
		CHECK(parse_fails(bad, "signature size"), "signature range past the end of the file rejected");

		bad = copy(pristine);
		put_le32(bad.data + signature + 8, 16);
		CHECK(parse_fails(bad, "signature offset"), "signature overlapping the load commands rejected");

		bad = copy(pristine);
		put_le32(bad.data + load_command_offset(&bad, 0x1b), 0x1d);
		CHECK(parse_fails(bad, "two signatures"), "two LC_CODE_SIGNATURE commands rejected");

		bad = copy(pristine);
		put_le32(bad.data + 20, 0xfffffff0u);
		CHECK(parse_fails(bad, "sizeofcmds"), "load commands past the end of the file rejected");

		bad = copy(pristine);
		put_le32(bad.data + signature + 4, 0);
		CHECK(parse_fails(bad, "cmdsize"), "zero-sized load command rejected");

		bad = copy(pristine);
		put_le32(bad.data, 0xcffaedfeu);
		CHECK(parse_fails(bad, "big-endian"), "byte-swapped Mach-O header rejected");

		bad = copy(pristine);
		bad.size = 3;
		CHECK(parse_fails(bad, "tiny"), "file shorter than a magic rejected");
	}

	free(pristine.data);
}

static int lookup(const char* xml, const char* key, enum dc_cs_entitlement_value* value) {
	const char* keys[] = { key };
	return dc_cs_entitlements_lookup((const uint8_t*)xml, strlen(xml), keys, 1, value);
}

#define PLIST_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">"

static void test_entitlements(void) {
	enum dc_cs_entitlement_value value;

	{
		struct buffer plist = load("ent.plist");
		const char* keys[] = { "com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation" };
		enum dc_cs_entitlement_value values[2];
		CHECK(dc_cs_entitlements_lookup(plist.data, plist.size, keys, 2, values) == 0 && values[0] == DC_CS_ENTITLEMENT_TRUE && values[1] == DC_CS_ENTITLEMENT_FALSE, "entitlements: the fixture's source plist");

		// trailing NUL bytes are padding
		uint8_t* padded = calloc(plist.size + 4, 1);
		memcpy(padded, plist.data, plist.size);
		CHECK(dc_cs_entitlements_lookup(padded, plist.size + 4, keys, 2, values) == 0 && values[0] == DC_CS_ENTITLEMENT_TRUE, "entitlements: trailing NUL bytes ignored");
		free(padded);
		free(plist.data);
	}

	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><true/><!-- c --><key>b</key><false/></dict></plist>", "b", &value) == 0 && value == DC_CS_ENTITLEMENT_FALSE, "entitlements: comments between entries");
	CHECK(lookup(PLIST_HEAD "<dict><key>outer</key><dict><key>a</key><true/></dict></dict></plist>", "a", &value) == 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: keys of nested dictionaries are not top-level keys");
	CHECK(lookup(PLIST_HEAD "<dict/></plist>", "a", &value) == 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: empty dictionary");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><array><true/></array></dict></plist>", "a", &value) == 0 && value == DC_CS_ENTITLEMENT_OTHER, "entitlements: array value is not a boolean");

	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><true/><key>a</key><false/></dict></plist>", "a", &value) != 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: duplicate key rejects the document");
	CHECK(lookup(PLIST_HEAD "<dict><key>b</key><true/><key>a</key><true/><key>b</key><false/></dict></plist>", "a", &value) != 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: duplicate of another key rejects the document");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><true>x</true></dict></plist>", "a", &value) != 0, "entitlements: <true> with content rejected");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><true x=\"1\"/></dict></plist>", "a", &value) != 0, "entitlements: <true> with an attribute rejected");
	CHECK(lookup(PLIST_HEAD "<dict><key>a<b/></key><true/></dict></plist>", "a", &value) != 0, "entitlements: key with an element inside rejected");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key></dict></plist>", "a", &value) != 0, "entitlements: key without a value rejected");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><bogus/></dict></plist>", "a", &value) != 0, "entitlements: unknown value element rejected");
	CHECK(lookup(PLIST_HEAD "<array><true/></array></plist>", "a", &value) != 0, "entitlements: array root rejected");
	CHECK(lookup(PLIST_HEAD "<dict/><dict/></plist>", "a", &value) != 0, "entitlements: two dictionaries rejected");
	CHECK(lookup("<dict><key>a</key><true/></dict>", "a", &value) != 0, "entitlements: missing <plist> rejected");
	CHECK(lookup(PLIST_HEAD "<dict><key>a</key><true/></dict>", "a", &value) != 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: malformed XML rejected");
	CHECK(lookup("<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY t \"a\">]><plist><dict><key>&t;</key><true/></dict></plist>", "a", &value) != 0 && value == DC_CS_ENTITLEMENT_ABSENT, "entitlements: entity declarations rejected");
	CHECK(lookup("<?xml version=\"1.0\"?><!DOCTYPE plist [<!ENTITY a \"x\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;\">]><plist><dict><key>k</key><string>&c;</string></dict></plist>", "k", &value) != 0, "entitlements: nested entity expansion rejected");
	CHECK(lookup("<?xml version=\"1.0\"?><!DOCTYPE plist SYSTEM \"file:///nonexistent/plist.dtd\"><plist><dict><key>a</key><true/></dict></plist>", "a", &value) == 0 && value == DC_CS_ENTITLEMENT_TRUE, "entitlements: an external DTD is not loaded");
	CHECK(lookup("", "a", &value) != 0, "entitlements: empty document rejected");

	{
		size_t size = DC_CS_ENTITLEMENTS_MAX + 1;
		uint8_t* big = malloc(size);
		memset(big, ' ', size);
		CHECK(dc_cs_entitlements_lookup(big, size, NULL, 0, &value) != 0, "entitlements: document over the size limit rejected");
		free(big);
	}
}

int main(int argc, char** argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s <fixture directory>\n", argv[0]);
		return 2;
	}
	fixture_dir = argv[1];

	test_valid_fixtures();
	test_fat();
	test_tampering();
	test_entitlements();

	printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
