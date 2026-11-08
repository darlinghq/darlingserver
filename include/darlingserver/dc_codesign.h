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

#ifndef _DARLINGSERVER_DC_CODESIGN_H_
#define _DARLINGSERVER_DC_CODESIGN_H_

/*
 * A bounded parser for the code signatures embedded in Mach-O images
 * (the `LC_CODE_SIGNATURE` SuperBlob with its CodeDirectories, requirements,
 * entitlements and CMS blobs), shared by darlingserver and mldr.
 *
 * Host-side code only. The parser never allocates and never writes to the
 * input: the results point into the caller's buffers, which must outlive them.
 * Every offset and length read from the input is checked against the buffer
 * that contains it before it is used. Digests are computed with OpenSSL's
 * libcrypto.
 *
 * The format and constants are those of the public `<kern/cs_blobs.h>`,
 * `<mach-o/loader.h>` and `<mach-o/fat.h>` headers.
 *
 * Functions that can fail return 0 on success and -1 on failure; when
 * `err`/`errlen` describe a buffer, a NUL-terminated reason is written to it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the truncated CodeDirectory hash that identifies a signature (`CS_CDHASH_LEN`) */
#define DC_CS_CDHASH_LEN 20

/* the largest digest of any supported hash type (`CS_HASH_MAX_SIZE`) */
#define DC_CS_HASH_MAX_SIZE 48

/* limits this parser imposes; inputs beyond them are rejected */
#define DC_CS_MAX_BLOBS 64
#define DC_CS_MAX_CODEDIRECTORIES 6
#define DC_CS_IDENTIFIER_MAX 512
#define DC_CS_TEAM_ID_MAX 64
#define DC_CS_FAT_MAX_ARCHS 64

/* the size of a buffer that always holds a whole fat header and its arch table */
#define DC_CS_FAT_HEADER_MAX (8 + DC_CS_FAT_MAX_ARCHS * 32)

/* the size of a buffer that always holds a Mach-O header (without load commands) */
#define DC_CS_MACHO_HEADER_MAX 32

/* `dc_cs_locate()` and `dc_cs_parse()` return this for an image without a signature */
#define DC_CS_UNSIGNED 1

struct dc_cs_blob {
	uint32_t type;   /* the SuperBlob index type (a `CSSLOT_*` value) */
	uint32_t offset; /* from the start of the SuperBlob */
	uint32_t length; /* the blob's own length field, header included */
	uint32_t magic;
};

struct dc_cs_codedirectory {
	const uint8_t* data; /* the whole blob, header included */
	uint32_t length;
	uint32_t slot;       /* `CSSLOT_CODEDIRECTORY` or a `CSSLOT_ALTERNATE_CODEDIRECTORIES` slot */
	uint8_t hash_type;   /* `CS_HASHTYPE_*` */
	uint8_t digest_length;
	uint8_t digest[DC_CS_HASH_MAX_SIZE]; /* the full digest of the blob, with its own hash type */
};

struct dc_cs_image {
	/* the Mach-O image (a thin file, or one slice of a fat file) */
	uint64_t size;
	uint32_t cputype;
	uint32_t cpusubtype;
	bool is_64;
	uint64_t load_commands_end; /* header plus `sizeofcmds` */

	/* the `LC_CODE_SIGNATURE` range, relative to the image */
	uint64_t signature_offset;
	uint32_t signature_size;

	/* the SuperBlob */
	const uint8_t* signature;
	uint32_t superblob_length;
	uint32_t blob_count;
	struct dc_cs_blob blobs[DC_CS_MAX_BLOBS];

	/* every CodeDirectory, in index order */
	uint32_t codedirectory_count;
	struct dc_cs_codedirectory codedirectories[DC_CS_MAX_CODEDIRECTORIES];

	/*
	 * The CodeDirectory that is used: the one with the strongest hash type.
	 * The fields below describe it.
	 */
	const struct dc_cs_codedirectory* codedirectory;
	uint32_t cd_version;
	uint32_t cd_flags; /* `CS_*` flags from the CodeDirectory */
	uint8_t hash_type;
	uint8_t hash_size;
	uint8_t platform;
	uint8_t page_size_log2;
	uint32_t hash_offset;
	uint32_t special_slot_count;
	uint32_t code_slot_count;
	uint64_t code_limit;
	uint64_t exec_seg_base;   /* 0 before version `CS_SUPPORTSEXECSEG` */
	uint64_t exec_seg_limit;
	uint64_t exec_seg_flags;  /* `CS_EXECSEG_*` */
	uint32_t runtime_version; /* 0 before version `CS_SUPPORTSRUNTIME` */
	char identifier[DC_CS_IDENTIFIER_MAX];
	char team_id[DC_CS_TEAM_ID_MAX]; /* empty when there is none */
	uint8_t cdhash[DC_CS_CDHASH_LEN];
	bool info_plist_bound;     /* special slot `CSSLOT_INFOSLOT` is set (not verified here) */
	bool resources_bound;      /* special slot `CSSLOT_RESOURCEDIR` is set (not verified here) */

	/* blobs bound to the CodeDirectories through their special slots (whole blobs, headers included) */
	const uint8_t* requirements;
	uint32_t requirements_length;
	const uint8_t* entitlements;     /* `CSMAGIC_EMBEDDED_ENTITLEMENTS` */
	uint32_t entitlements_length;
	const uint8_t* der_entitlements; /* `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` */
	uint32_t der_entitlements_length;

	/* the CMS signature: the payload of the `CSSLOT_SIGNATURESLOT` wrapper; empty when ad-hoc */
	const uint8_t* cms;
	uint32_t cms_length;
};

/**
 * Finds the image that starts at @p offset in a file of @p file_size bytes.
 *
 * @p head holds the first @p head_length bytes of the file; it must contain the whole fat header
 * and arch table (`DC_CS_FAT_HEADER_MAX` bytes always suffice).
 *
 * For a thin Mach-O, @p offset must be 0 and the image is the whole file. For a fat file
 * (`FAT_MAGIC` or `FAT_MAGIC_64`), @p offset must be the offset of one of its slices; the table
 * is validated completely (every slice inside the file, slices not overlapping the table or each
 * other).
 *
 * @param image_size Receives the size of the image.
 */
int dc_cs_image_at(const uint8_t* head, size_t head_length, uint64_t file_size, uint64_t offset, uint64_t* image_size, char* err, size_t errlen);

/**
 * Returns how many bytes from the start of the image `dc_cs_locate()` needs: the Mach-O header
 * and its load commands. @p head must hold at least `DC_CS_MACHO_HEADER_MAX` bytes of the
 * image (or the whole image, if it is shorter).
 */
int dc_cs_header_length(const uint8_t* head, size_t head_length, uint64_t image_size, uint64_t* needed, char* err, size_t errlen);

/**
 * Parses the Mach-O header and load commands of an image of @p image_size bytes and finds its
 * signature. @p head must hold at least the number of bytes `dc_cs_header_length()` returned.
 * Clears @p image first.
 *
 * Only little-endian images (`MH_MAGIC`, `MH_MAGIC_64`) are accepted.
 *
 * @returns 0 if the image has a signature (`signature_offset` and `signature_size` say where),
 *          `DC_CS_UNSIGNED` if it has none, or -1 if the image is malformed.
 */
int dc_cs_locate(const uint8_t* head, size_t head_length, uint64_t image_size, struct dc_cs_image* image, char* err, size_t errlen);

/**
 * Parses the signature that `dc_cs_locate()` found. @p signature holds the `signature_size`
 * bytes at `signature_offset`.
 *
 * Validates the SuperBlob, every CodeDirectory, and the requirements and entitlement blobs
 * against the special slots of every CodeDirectory, then selects the CodeDirectory with the
 * strongest hash type. Code pages are not looked at; see `dc_cs_verify_page()`.
 */
int dc_cs_parse_signature(const uint8_t* signature, size_t signature_length, struct dc_cs_image* image, char* err, size_t errlen);

/**
 * `dc_cs_locate()` and `dc_cs_parse_signature()` for an image that is entirely in memory.
 *
 * @returns 0, `DC_CS_UNSIGNED` or -1, as `dc_cs_locate()`.
 */
int dc_cs_parse(const uint8_t* data, size_t size, struct dc_cs_image* image, char* err, size_t errlen);

/**
 * The number of bytes that code page @p index covers (the last page may be short), or 0 if
 * there is no such page.
 */
uint64_t dc_cs_page_length(const struct dc_cs_image* image, uint32_t index);

/**
 * Checks code page @p index against the selected CodeDirectory. @p length must be
 * `dc_cs_page_length(image, index)`.
 *
 * @returns 0 if the page matches, -1 if it does not (or the arguments are wrong).
 */
int dc_cs_verify_page(const struct dc_cs_image* image, uint32_t index, const uint8_t* page, size_t length);

/**
 * Checks every code page of an image that is entirely in memory.
 *
 * @param first_bad_page Receives the index of the first page that does not match (may be NULL).
 */
int dc_cs_verify_pages(const struct dc_cs_image* image, const uint8_t* data, size_t size, uint32_t* first_bad_page, char* err, size_t errlen);

/**
 * Computes the digest of @p hash_type (`CS_HASHTYPE_*`) over @p length bytes, as the
 * CodeDirectory uses it (`CS_HASHTYPE_SHA256_TRUNCATED` yields 20 bytes).
 *
 * @param out Must hold `DC_CS_HASH_MAX_SIZE` bytes.
 * @param out_length Receives the digest length.
 */
int dc_cs_digest(uint8_t hash_type, const void* data, size_t length, uint8_t* out, size_t* out_length);

#ifdef __cplusplus
}
#endif

#endif // _DARLINGSERVER_DC_CODESIGN_H_
