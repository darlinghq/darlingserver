/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Darling Developers
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

#include <darlingserver/dc_codesign.h>

#include <kern/cs_blobs.h>

#include <openssl/evp.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "macho-format.h"

/*
 * The imported <kern/cs_blobs.h> predates DER entitlements. Newer versions of
 * the public header add this slot and magic (`CSSLOT_DER_ENTITLEMENTS` and
 * `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`); `codesign` writes them (see the
 * adhoc-runtime-ent test fixture).
 */
#define DC_CSSLOT_DER_ENTITLEMENTS 7u
#define DC_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172u

/* the oldest CodeDirectory version this parser accepts, and the first one it does not */
#define DC_CS_CD_VERSION_MIN 0x20001u
#define DC_CS_CD_VERSION_LIMIT 0x30000u

/* supported page sizes (log2); `codesign` uses 4 KiB and 16 KiB */
#define DC_CS_PAGE_SIZE_LOG2_MIN 12u
#define DC_CS_PAGE_SIZE_LOG2_MAX 16u

_Static_assert(DC_CS_CDHASH_LEN == CS_CDHASH_LEN, "must match <kern/cs_blobs.h>");
_Static_assert(DC_CS_HASH_MAX_SIZE == CS_HASH_MAX_SIZE, "must match <kern/cs_blobs.h>");
_Static_assert(DC_CS_MAX_CODEDIRECTORIES == 1 + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX, "one primary and every alternate CodeDirectory");
_Static_assert(DC_CS_FAT_HEADER_MAX >= DC_FAT_HEADER_SIZE + DC_CS_FAT_MAX_ARCHS * DC_FAT_ARCH_64_SIZE, "fat header buffer size");
_Static_assert(DC_CS_MACHO_HEADER_MAX >= DC_MACH_HEADER_64_SIZE, "Mach-O header buffer size");

static int fail(char* err, size_t errlen, const char* format, ...) __attribute__((format(printf, 3, 4)));

static int fail(char* err, size_t errlen, const char* format, ...) {
	if (err && errlen > 0) {
		va_list args;
		va_start(args, format);
		vsnprintf(err, errlen, format, args);
		va_end(args);
	}
	return -1;
}

static uint32_t read_be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t read_be64(const uint8_t* p) {
	return ((uint64_t)read_be32(p) << 32) | read_be32(p + 4);
}

static uint32_t read_le32(const uint8_t* p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// whether [offset, offset + length) lies within [0, total), without overflowing
static bool in_range(uint64_t total, uint64_t offset, uint64_t length) {
	return offset <= total && length <= total - offset;
}

static bool ranges_overlap(uint64_t a_offset, uint64_t a_length, uint64_t b_offset, uint64_t b_length) {
	// both ranges were checked with `in_range` against the same total, so the sums cannot overflow
	return a_offset < b_offset + b_length && b_offset < a_offset + a_length;
}

static int expected_hash_size(uint8_t hash_type) {
	switch (hash_type) {
		case CS_HASHTYPE_SHA1:             return CS_SHA1_LEN;
		case CS_HASHTYPE_SHA256:           return CS_SHA256_LEN;
		case CS_HASHTYPE_SHA256_TRUNCATED: return CS_SHA256_TRUNCATED_LEN;
		case CS_HASHTYPE_SHA384:           return CS_HASH_MAX_SIZE;
		default:                           return -1;
	}
}

// a larger rank is a stronger hash; 0 for an unsupported type
static unsigned hash_rank(uint8_t hash_type) {
	switch (hash_type) {
		case CS_HASHTYPE_SHA1:             return 1;
		case CS_HASHTYPE_SHA256_TRUNCATED: return 2;
		case CS_HASHTYPE_SHA256:           return 3;
		case CS_HASHTYPE_SHA384:           return 4;
		default:                           return 0;
	}
}

int dc_cs_digest(uint8_t hash_type, const void* data, size_t length, uint8_t* out, size_t* out_length) {
	const EVP_MD* md = NULL;
	uint8_t full[EVP_MAX_MD_SIZE];
	unsigned int full_length = 0;
	int size = expected_hash_size(hash_type);

	switch (hash_type) {
		case CS_HASHTYPE_SHA1:             md = EVP_sha1();   break;
		case CS_HASHTYPE_SHA256:
		case CS_HASHTYPE_SHA256_TRUNCATED: md = EVP_sha256(); break;
		case CS_HASHTYPE_SHA384:           md = EVP_sha384(); break;
		default:                           return -1;
	}

	if (EVP_Digest(data, length, full, &full_length, md, NULL) != 1 || size < 0 || full_length < (unsigned int)size) {
		return -1;
	}

	memcpy(out, full, (size_t)size);
	if (out_length) {
		*out_length = (size_t)size;
	}
	return 0;
}

int dc_cs_image_at(const uint8_t* head, size_t head_length, uint64_t file_size, uint64_t offset, uint64_t* image_size, char* err, size_t errlen) {
	if (!head || !image_size) {
		return fail(err, errlen, "null argument");
	}
	if (head_length > file_size) {
		head_length = (size_t)file_size;
	}
	if (head_length < 4) {
		return fail(err, errlen, "file is too short to be a Mach-O file");
	}

	uint32_t magic = read_be32(head);
	if (magic == DC_FAT_MAGIC || magic == DC_FAT_MAGIC_64) {
		bool is_64 = (magic == DC_FAT_MAGIC_64);
		uint64_t entry_size = is_64 ? DC_FAT_ARCH_64_SIZE : DC_FAT_ARCH_SIZE;

		if (head_length < DC_FAT_HEADER_SIZE) {
			return fail(err, errlen, "truncated fat header");
		}

		uint32_t count = read_be32(head + 4);
		if (count == 0 || count > DC_CS_FAT_MAX_ARCHS) {
			return fail(err, errlen, "unsupported number of fat slices (%u)", count);
		}

		uint64_t table_end = DC_FAT_HEADER_SIZE + (uint64_t)count * entry_size;
		if (table_end > head_length) {
			return fail(err, errlen, "fat arch table is not in the buffer");
		}

		uint64_t offsets[DC_CS_FAT_MAX_ARCHS];
		uint64_t sizes[DC_CS_FAT_MAX_ARCHS];
		bool found = false;

		for (uint32_t i = 0; i < count; ++i) {
			const uint8_t* entry = head + DC_FAT_HEADER_SIZE + i * entry_size;
			uint64_t slice_offset = is_64 ? read_be64(entry + 8) : read_be32(entry + 8);
			uint64_t slice_size = is_64 ? read_be64(entry + 16) : read_be32(entry + 12);

			if (slice_size == 0 || !in_range(file_size, slice_offset, slice_size)) {
				return fail(err, errlen, "fat slice %u lies outside the file", i);
			}
			if (slice_offset < table_end) {
				return fail(err, errlen, "fat slice %u overlaps the fat header", i);
			}
			for (uint32_t j = 0; j < i; ++j) {
				if (ranges_overlap(slice_offset, slice_size, offsets[j], sizes[j])) {
					return fail(err, errlen, "fat slices %u and %u overlap", j, i);
				}
			}

			offsets[i] = slice_offset;
			sizes[i] = slice_size;

			if (slice_offset == offset) {
				*image_size = slice_size;
				found = true;
			}
		}

		if (!found) {
			return fail(err, errlen, "no fat slice starts at offset %llu", (unsigned long long)offset);
		}
		return 0;
	}

	magic = read_le32(head);
	if (magic == DC_MH_MAGIC || magic == DC_MH_MAGIC_64) {
		if (offset != 0) {
			return fail(err, errlen, "a thin Mach-O file has only one image, at offset 0");
		}
		*image_size = file_size;
		return 0;
	}

	return fail(err, errlen, "not a little-endian Mach-O or fat file (magic 0x%08x)", read_be32(head));
}

int dc_cs_header_length(const uint8_t* head, size_t head_length, uint64_t image_size, uint64_t* needed, char* err, size_t errlen) {
	if (!head || !needed) {
		return fail(err, errlen, "null argument");
	}
	if (head_length > image_size) {
		head_length = (size_t)image_size;
	}
	if (head_length < 4) {
		return fail(err, errlen, "image is too short to be a Mach-O image");
	}

	uint32_t magic = read_le32(head);
	uint64_t header_size;
	if (magic == DC_MH_MAGIC_64) {
		header_size = DC_MACH_HEADER_64_SIZE;
	} else if (magic == DC_MH_MAGIC) {
		header_size = DC_MACH_HEADER_SIZE;
	} else {
		return fail(err, errlen, "not a little-endian Mach-O image (magic 0x%08x)", read_be32(head));
	}

	if (head_length < header_size) {
		return fail(err, errlen, "truncated Mach-O header");
	}

	uint32_t sizeofcmds = read_le32(head + 20);
	if (!in_range(image_size, header_size, sizeofcmds)) {
		return fail(err, errlen, "load commands run past the end of the image");
	}

	*needed = header_size + sizeofcmds;
	return 0;
}

int dc_cs_locate(const uint8_t* head, size_t head_length, uint64_t image_size, struct dc_cs_image* image, char* err, size_t errlen) {
	uint64_t needed = 0;

	if (!head || !image) {
		return fail(err, errlen, "null argument");
	}

	memset(image, 0, sizeof(*image));
	image->size = image_size;

	if (dc_cs_header_length(head, head_length, image_size, &needed, err, errlen) != 0) {
		return -1;
	}
	if (head_length < needed) {
		return fail(err, errlen, "load commands are not in the buffer");
	}

	image->is_64 = (read_le32(head) == DC_MH_MAGIC_64);
	image->cputype = read_le32(head + 4);
	image->cpusubtype = read_le32(head + 8);
	image->load_commands_end = needed;

	uint32_t command_count = read_le32(head + 16);
	uint64_t position = image->is_64 ? DC_MACH_HEADER_64_SIZE : DC_MACH_HEADER_SIZE;
	unsigned found = 0;
	uint32_t data_offset = 0;
	uint32_t data_size = 0;

	for (uint32_t i = 0; i < command_count; ++i) {
		if (!in_range(needed, position, 8)) {
			return fail(err, errlen, "load command %u runs past the load commands", i);
		}

		uint32_t command = read_le32(head + position);
		uint32_t command_size = read_le32(head + position + 4);

		if (command_size < 8 || !in_range(needed, position, command_size)) {
			return fail(err, errlen, "load command %u has a bad size (%u)", i, command_size);
		}

		if (command == DC_LC_CODE_SIGNATURE) {
			if (command_size < DC_LINKEDIT_DATA_COMMAND_SIZE) {
				return fail(err, errlen, "LC_CODE_SIGNATURE is too small");
			}
			data_offset = read_le32(head + position + 8);
			data_size = read_le32(head + position + 12);
			++found;
		}

		position += command_size;
	}

	if (found == 0) {
		return DC_CS_UNSIGNED;
	}
	if (found > 1) {
		return fail(err, errlen, "more than one LC_CODE_SIGNATURE");
	}
	if (!in_range(image_size, data_offset, data_size)) {
		return fail(err, errlen, "the signature lies outside the image");
	}
	if (data_offset < needed) {
		return fail(err, errlen, "the signature overlaps the load commands");
	}
	if (data_size < 12) {
		return fail(err, errlen, "the signature is smaller than a SuperBlob header");
	}

	image->signature_offset = data_offset;
	image->signature_size = data_size;
	return 0;
}

// what one CodeDirectory says; filled in by `parse_codedirectory`
struct cd_info {
	uint32_t version;
	uint32_t flags;
	uint8_t hash_type;
	uint8_t hash_size;
	uint8_t platform;
	uint8_t page_size_log2;
	uint32_t hash_offset;
	uint32_t special_slot_count;
	uint32_t code_slot_count;
	uint64_t code_limit;
	uint64_t exec_seg_base;
	uint64_t exec_seg_limit;
	uint64_t exec_seg_flags;
	uint32_t runtime_version;
	const char* identifier;
	size_t identifier_length;
	const char* team_id; // NULL when absent
	size_t team_id_length;
};

// the size of the fixed part of a CodeDirectory of this version
static uint64_t cd_fixed_size(uint32_t version) {
	if (version >= CS_SUPPORTSLINKAGE) {
		return offsetof(CS_CodeDirectory, end_withLinkage);
	} else if (version >= CS_SUPPORTSRUNTIME) {
		return offsetof(CS_CodeDirectory, end_withPreEncryptOffset);
	} else if (version >= CS_SUPPORTSEXECSEG) {
		return offsetof(CS_CodeDirectory, end_withExecSeg);
	} else if (version >= CS_SUPPORTSCODELIMIT64) {
		return offsetof(CS_CodeDirectory, end_withCodeLimit64);
	} else if (version >= CS_SUPPORTSTEAMID) {
		return offsetof(CS_CodeDirectory, end_withTeam);
	} else if (version >= CS_SUPPORTSSCATTER) {
		return offsetof(CS_CodeDirectory, end_withScatter);
	}
	return offsetof(CS_CodeDirectory, end_earliest);
}

// reads a NUL-terminated string that starts at `offset` and ends inside the CodeDirectory
static int cd_string(const uint8_t* cd, uint32_t cd_length, uint64_t fixed_size, uint32_t offset, size_t limit, const char** out, size_t* out_length) {
	if (offset < fixed_size || offset >= cd_length) {
		return -1;
	}
	size_t length = strnlen((const char*)cd + offset, cd_length - offset);
	if (length == cd_length - offset || length >= limit) {
		// not terminated within the blob, or too long for us
		return -1;
	}
	*out = (const char*)cd + offset;
	*out_length = length;
	return 0;
}

static int parse_codedirectory(const struct dc_cs_image* image, const uint8_t* cd, uint32_t cd_length, struct cd_info* info, char* err, size_t errlen) {
	memset(info, 0, sizeof(*info));

	if (cd_length < offsetof(CS_CodeDirectory, end_earliest)) {
		return fail(err, errlen, "CodeDirectory is shorter than its header");
	}

	info->version = read_be32(cd + offsetof(CS_CodeDirectory, version));
	info->flags = read_be32(cd + offsetof(CS_CodeDirectory, flags));
	info->hash_offset = read_be32(cd + offsetof(CS_CodeDirectory, hashOffset));
	uint32_t identifier_offset = read_be32(cd + offsetof(CS_CodeDirectory, identOffset));
	info->special_slot_count = read_be32(cd + offsetof(CS_CodeDirectory, nSpecialSlots));
	info->code_slot_count = read_be32(cd + offsetof(CS_CodeDirectory, nCodeSlots));
	uint32_t code_limit32 = read_be32(cd + offsetof(CS_CodeDirectory, codeLimit));
	info->hash_size = cd[offsetof(CS_CodeDirectory, hashSize)];
	info->hash_type = cd[offsetof(CS_CodeDirectory, hashType)];
	info->platform = cd[offsetof(CS_CodeDirectory, platform)];
	info->page_size_log2 = cd[offsetof(CS_CodeDirectory, pageSize)];

	if (info->version < DC_CS_CD_VERSION_MIN || info->version >= DC_CS_CD_VERSION_LIMIT) {
		return fail(err, errlen, "unsupported CodeDirectory version 0x%x", info->version);
	}

	uint64_t fixed_size = cd_fixed_size(info->version);
	if (cd_length < fixed_size) {
		return fail(err, errlen, "CodeDirectory version 0x%x is truncated", info->version);
	}

	if (read_be32(cd + offsetof(CS_CodeDirectory, spare2)) != 0) {
		return fail(err, errlen, "CodeDirectory spare2 is not zero");
	}

	int expected_size = expected_hash_size(info->hash_type);
	if (expected_size < 0) {
		return fail(err, errlen, "unsupported hash type %u", info->hash_type);
	}
	if (info->hash_size != expected_size) {
		return fail(err, errlen, "hash size %u does not match hash type %u", info->hash_size, info->hash_type);
	}

	if (info->page_size_log2 < DC_CS_PAGE_SIZE_LOG2_MIN || info->page_size_log2 > DC_CS_PAGE_SIZE_LOG2_MAX) {
		return fail(err, errlen, "unsupported page size 2^%u", info->page_size_log2);
	}

	if (info->version >= CS_SUPPORTSSCATTER && read_be32(cd + offsetof(CS_CodeDirectory, scatterOffset)) != 0) {
		return fail(err, errlen, "scatter vectors are not supported");
	}

	info->code_limit = code_limit32;
	if (info->version >= CS_SUPPORTSCODELIMIT64) {
		uint64_t code_limit64 = read_be64(cd + offsetof(CS_CodeDirectory, codeLimit64));
		if (code_limit64 != 0) {
			if (code_limit32 != 0) {
				return fail(err, errlen, "both codeLimit and codeLimit64 are set");
			}
			info->code_limit = code_limit64;
		}
	}

	if (info->version >= CS_SUPPORTSEXECSEG) {
		info->exec_seg_base = read_be64(cd + offsetof(CS_CodeDirectory, execSegBase));
		info->exec_seg_limit = read_be64(cd + offsetof(CS_CodeDirectory, execSegLimit));
		info->exec_seg_flags = read_be64(cd + offsetof(CS_CodeDirectory, execSegFlags));
	}

	if (info->version >= CS_SUPPORTSRUNTIME) {
		info->runtime_version = read_be32(cd + offsetof(CS_CodeDirectory, runtime));
	}

	// the signed range must cover the Mach-O header and load commands, and must not reach into the signature
	if (info->code_limit < image->load_commands_end) {
		return fail(err, errlen, "the code limit does not cover the load commands");
	}
	if (info->code_limit > image->signature_offset) {
		return fail(err, errlen, "the code limit reaches into the signature");
	}

	uint64_t page_size = 1ull << info->page_size_log2;
	uint64_t expected_slots = (info->code_limit + page_size - 1) / page_size;
	if (expected_slots != info->code_slot_count) {
		return fail(err, errlen, "%u code slots do not match a code limit of %llu", info->code_slot_count, (unsigned long long)info->code_limit);
	}

	// the hash slots, special ones included, must lie between the fixed fields and the end of the blob
	uint64_t special_bytes = (uint64_t)info->special_slot_count * info->hash_size;
	uint64_t code_bytes = (uint64_t)info->code_slot_count * info->hash_size;
	if (info->hash_offset < fixed_size || special_bytes > info->hash_offset - fixed_size) {
		return fail(err, errlen, "special slots overlap the CodeDirectory header");
	}
	if (!in_range(cd_length, info->hash_offset, code_bytes)) {
		return fail(err, errlen, "code slots run past the CodeDirectory");
	}

	if (cd_string(cd, cd_length, fixed_size, identifier_offset, DC_CS_IDENTIFIER_MAX, &info->identifier, &info->identifier_length) != 0) {
		return fail(err, errlen, "bad identifier");
	}

	if (info->version >= CS_SUPPORTSTEAMID) {
		uint32_t team_offset = read_be32(cd + offsetof(CS_CodeDirectory, teamOffset));
		if (team_offset != 0 && cd_string(cd, cd_length, fixed_size, team_offset, DC_CS_TEAM_ID_MAX, &info->team_id, &info->team_id_length) != 0) {
			return fail(err, errlen, "bad team identifier");
		}
	}

	return 0;
}

static const uint8_t* special_slot(const uint8_t* cd, const struct cd_info* info, uint32_t slot) {
	// `parse_codedirectory` made sure that every special slot lies inside the blob
	return cd + info->hash_offset - (size_t)slot * info->hash_size;
}

static bool slot_is_zero(const uint8_t* hash, uint8_t size) {
	for (uint8_t i = 0; i < size; ++i) {
		if (hash[i] != 0) {
			return false;
		}
	}
	return true;
}

/*
 * Checks that the special slot @p slot of a CodeDirectory binds the blob of the same type: when
 * the slot is set, the blob must be present with the right magic and the slot must hold its hash;
 * when the blob is present, the CodeDirectory must have the slot.
 */
static int check_special_slot(const struct dc_cs_image* image, const uint8_t* cd, const struct cd_info* info, uint32_t slot, uint32_t magic, char* err, size_t errlen) {
	const struct dc_cs_blob* blob = NULL;

	for (uint32_t i = 0; i < image->blob_count; ++i) {
		if (image->blobs[i].type == slot) {
			blob = &image->blobs[i];
			break;
		}
	}

	if (slot > info->special_slot_count) {
		if (blob) {
			return fail(err, errlen, "blob type %u is not bound by the CodeDirectory", slot);
		}
		return 0;
	}

	const uint8_t* hash = special_slot(cd, info, slot);

	if (!blob) {
		if (!slot_is_zero(hash, info->hash_size)) {
			return fail(err, errlen, "special slot %u is set but its blob is missing", slot);
		}
		return 0;
	}

	if (blob->magic != magic) {
		return fail(err, errlen, "blob type %u has the wrong magic 0x%08x", slot, blob->magic);
	}

	uint8_t digest[DC_CS_HASH_MAX_SIZE];
	size_t digest_length = 0;
	if (dc_cs_digest(info->hash_type, image->signature + blob->offset, blob->length, digest, &digest_length) != 0 ||
		digest_length != info->hash_size || memcmp(digest, hash, digest_length) != 0)
	{
		return fail(err, errlen, "special slot %u does not match its blob", slot);
	}

	return 0;
}

int dc_cs_parse_signature(const uint8_t* signature, size_t signature_length, struct dc_cs_image* image, char* err, size_t errlen) {
	if (!signature || !image) {
		return fail(err, errlen, "null argument");
	}
	if (image->signature_size == 0 || signature_length != image->signature_size) {
		return fail(err, errlen, "the buffer does not hold the located signature");
	}

	uint32_t magic = read_be32(signature);
	uint32_t length = read_be32(signature + 4);
	uint32_t count = read_be32(signature + 8);

	if (magic != CSMAGIC_EMBEDDED_SIGNATURE) {
		return fail(err, errlen, "bad SuperBlob magic 0x%08x", magic);
	}
	if (length < 12 || length > signature_length) {
		return fail(err, errlen, "SuperBlob length %u does not fit the signature", length);
	}
	if (count == 0 || count > DC_CS_MAX_BLOBS) {
		return fail(err, errlen, "unsupported number of blobs (%u)", count);
	}

	uint64_t index_end = 12 + (uint64_t)count * 8;
	if (index_end > length) {
		return fail(err, errlen, "the blob index runs past the SuperBlob");
	}

	image->signature = signature;
	image->superblob_length = length;
	image->blob_count = count;
	image->codedirectory_count = 0;

	for (uint32_t i = 0; i < count; ++i) {
		const uint8_t* entry = signature + 12 + i * 8;
		uint32_t type = read_be32(entry);
		uint32_t offset = read_be32(entry + 4);

		if (offset < index_end || !in_range(length, offset, 8)) {
			return fail(err, errlen, "blob %u starts outside the SuperBlob", i);
		}

		uint32_t blob_length = read_be32(signature + offset + 4);
		if (blob_length < 8 || !in_range(length, offset, blob_length)) {
			return fail(err, errlen, "blob %u runs past the SuperBlob", i);
		}

		for (uint32_t j = 0; j < i; ++j) {
			if (image->blobs[j].type == type) {
				return fail(err, errlen, "more than one blob of type 0x%x", type);
			}
		}

		image->blobs[i].type = type;
		image->blobs[i].offset = offset;
		image->blobs[i].length = blob_length;
		image->blobs[i].magic = read_be32(signature + offset);
	}

	const struct dc_cs_codedirectory* best = NULL;
	struct cd_info best_info;
	unsigned best_rank = 0;
	unsigned seen_ranks = 0;

	for (uint32_t i = 0; i < count; ++i) {
		const struct dc_cs_blob* blob = &image->blobs[i];

		if (blob->type != CSSLOT_CODEDIRECTORY && (blob->type < CSSLOT_ALTERNATE_CODEDIRECTORIES || blob->type >= CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
			continue;
		}
		if (blob->magic != CSMAGIC_CODEDIRECTORY) {
			return fail(err, errlen, "CodeDirectory slot 0x%x has the wrong magic 0x%08x", blob->type, blob->magic);
		}
		// at most one blob per slot type, so there can be no more CodeDirectories than slots
		if (image->codedirectory_count >= DC_CS_MAX_CODEDIRECTORIES) {
			return fail(err, errlen, "too many CodeDirectories");
		}

		const uint8_t* cd = signature + blob->offset;
		struct cd_info info;

		if (parse_codedirectory(image, cd, blob->length, &info, err, errlen) != 0) {
			return -1;
		}

		unsigned rank = hash_rank(info.hash_type);
		if ((seen_ranks & (1u << rank)) != 0) {
			return fail(err, errlen, "more than one CodeDirectory with hash type %u", info.hash_type);
		}
		seen_ranks |= 1u << rank;

		// every CodeDirectory must bind the same requirement and entitlement blobs
		if (check_special_slot(image, cd, &info, CSSLOT_REQUIREMENTS, CSMAGIC_REQUIREMENTS, err, errlen) != 0 ||
			check_special_slot(image, cd, &info, CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS, err, errlen) != 0 ||
			check_special_slot(image, cd, &info, DC_CSSLOT_DER_ENTITLEMENTS, DC_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, err, errlen) != 0)
		{
			return -1;
		}

		struct dc_cs_codedirectory* entry = &image->codedirectories[image->codedirectory_count++];
		entry->data = cd;
		entry->length = blob->length;
		entry->slot = blob->type;
		entry->hash_type = info.hash_type;

		size_t digest_length = 0;
		if (dc_cs_digest(info.hash_type, cd, blob->length, entry->digest, &digest_length) != 0 || digest_length < DC_CS_CDHASH_LEN) {
			return fail(err, errlen, "cannot hash the CodeDirectory");
		}
		entry->digest_length = (uint8_t)digest_length;

		if (rank > best_rank) {
			best = entry;
			best_info = info;
			best_rank = rank;
		}
	}

	if (!best) {
		return fail(err, errlen, "no CodeDirectory");
	}

	image->codedirectory = best;
	image->cd_version = best_info.version;
	image->cd_flags = best_info.flags;
	image->hash_type = best_info.hash_type;
	image->hash_size = best_info.hash_size;
	image->platform = best_info.platform;
	image->page_size_log2 = best_info.page_size_log2;
	image->hash_offset = best_info.hash_offset;
	image->special_slot_count = best_info.special_slot_count;
	image->code_slot_count = best_info.code_slot_count;
	image->code_limit = best_info.code_limit;
	image->exec_seg_base = best_info.exec_seg_base;
	image->exec_seg_limit = best_info.exec_seg_limit;
	image->exec_seg_flags = best_info.exec_seg_flags;
	image->runtime_version = best_info.runtime_version;
	memcpy(image->identifier, best_info.identifier, best_info.identifier_length);
	image->identifier[best_info.identifier_length] = '\0';
	if (best_info.team_id) {
		memcpy(image->team_id, best_info.team_id, best_info.team_id_length);
		image->team_id[best_info.team_id_length] = '\0';
	} else {
		image->team_id[0] = '\0';
	}
	memcpy(image->cdhash, best->digest, DC_CS_CDHASH_LEN);

	image->info_plist_bound = best_info.special_slot_count >= CSSLOT_INFOSLOT &&
		!slot_is_zero(special_slot(best->data, &best_info, CSSLOT_INFOSLOT), best_info.hash_size);
	image->resources_bound = best_info.special_slot_count >= CSSLOT_RESOURCEDIR &&
		!slot_is_zero(special_slot(best->data, &best_info, CSSLOT_RESOURCEDIR), best_info.hash_size);

	for (uint32_t i = 0; i < count; ++i) {
		const struct dc_cs_blob* blob = &image->blobs[i];
		const uint8_t* data = signature + blob->offset;

		switch (blob->type) {
			case CSSLOT_REQUIREMENTS:
				image->requirements = data;
				image->requirements_length = blob->length;
				break;
			case CSSLOT_ENTITLEMENTS:
				image->entitlements = data;
				image->entitlements_length = blob->length;
				break;
			case DC_CSSLOT_DER_ENTITLEMENTS:
				image->der_entitlements = data;
				image->der_entitlements_length = blob->length;
				break;
			case CSSLOT_SIGNATURESLOT:
				if (blob->magic != CSMAGIC_BLOBWRAPPER) {
					return fail(err, errlen, "the CMS slot has the wrong magic 0x%08x", blob->magic);
				}
				// an ad-hoc signature has an empty wrapper here
				image->cms = data + 8;
				image->cms_length = blob->length - 8;
				break;
			default:
				break;
		}
	}

	return 0;
}

int dc_cs_parse(const uint8_t* data, size_t size, struct dc_cs_image* image, char* err, size_t errlen) {
	if (!data || !image) {
		return fail(err, errlen, "null argument");
	}

	int result = dc_cs_locate(data, size, size, image, err, errlen);
	if (result != 0) {
		return result;
	}

	return dc_cs_parse_signature(data + image->signature_offset, image->signature_size, image, err, errlen);
}

uint64_t dc_cs_page_length(const struct dc_cs_image* image, uint32_t index) {
	if (!image || !image->codedirectory || index >= image->code_slot_count) {
		return 0;
	}

	uint64_t page_size = 1ull << image->page_size_log2;
	uint64_t start = (uint64_t)index * page_size;
	if (start >= image->code_limit) {
		return 0;
	}

	uint64_t remaining = image->code_limit - start;
	return remaining < page_size ? remaining : page_size;
}

int dc_cs_verify_page(const struct dc_cs_image* image, uint32_t index, const uint8_t* page, size_t length) {
	uint64_t expected_length = dc_cs_page_length(image, index);

	if (expected_length == 0 || !page || length != expected_length) {
		return -1;
	}

	uint8_t digest[DC_CS_HASH_MAX_SIZE];
	size_t digest_length = 0;
	if (dc_cs_digest(image->hash_type, page, length, digest, &digest_length) != 0 || digest_length != image->hash_size) {
		return -1;
	}

	// `parse_codedirectory` made sure that every code slot lies inside the blob
	const uint8_t* expected = image->codedirectory->data + image->hash_offset + (size_t)index * image->hash_size;
	return memcmp(digest, expected, digest_length) == 0 ? 0 : -1;
}

int dc_cs_verify_pages(const struct dc_cs_image* image, const uint8_t* data, size_t size, uint32_t* first_bad_page, char* err, size_t errlen) {
	if (!image || !image->codedirectory || !data) {
		return fail(err, errlen, "the image has not been parsed");
	}
	if (size != image->size) {
		return fail(err, errlen, "the buffer does not hold the parsed image");
	}

	uint64_t page_size = 1ull << image->page_size_log2;

	for (uint32_t i = 0; i < image->code_slot_count; ++i) {
		uint64_t offset = (uint64_t)i * page_size;
		uint64_t length = dc_cs_page_length(image, i);

		// the code limit is within the image, so every page is too
		if (dc_cs_verify_page(image, i, data + offset, (size_t)length) != 0) {
			if (first_bad_page) {
				*first_bad_page = i;
			}
			return fail(err, errlen, "code page %u does not match its hash", i);
		}
	}

	return 0;
}
