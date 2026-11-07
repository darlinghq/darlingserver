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

#ifndef _DARLINGSERVER_DC_ENTITLEMENTS_H_
#define _DARLINGSERVER_DC_ENTITLEMENTS_H_

/*
 * Looks up keys in the XML entitlements plist embedded in a code signature
 * (the payload of the `CSMAGIC_EMBEDDED_ENTITLEMENTS` blob).
 *
 * Host-side code only, built on libxml2. The document is parsed without
 * network access, without loading external DTDs and without substituting
 * entities; a document that declares entities, or that is not a single
 * `<plist>` holding one `<dict>`, or that repeats a top-level key, is
 * rejected as a whole. Only the top level of the dictionary is examined.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the largest entitlements document that is parsed */
#define DC_CS_ENTITLEMENTS_MAX (1024 * 1024)

enum dc_cs_entitlement_value {
	DC_CS_ENTITLEMENT_ABSENT = 0,
	DC_CS_ENTITLEMENT_TRUE,
	DC_CS_ENTITLEMENT_FALSE,
	/* present with a value that is not a boolean */
	DC_CS_ENTITLEMENT_OTHER,
};

/**
 * Looks up @p key_count keys in an entitlements plist of @p length bytes (trailing NUL bytes are
 * ignored) and stores one `dc_cs_entitlement_value` per key in @p values.
 *
 * @returns 0 if the document is well-formed, or -1 if it is not (or is larger than
 *          `DC_CS_ENTITLEMENTS_MAX`); every value is `DC_CS_ENTITLEMENT_ABSENT` then.
 */
int dc_cs_entitlements_lookup(const uint8_t* xml, size_t length, const char* const* keys, size_t key_count, enum dc_cs_entitlement_value* values);

#ifdef __cplusplus
}
#endif

#endif // _DARLINGSERVER_DC_ENTITLEMENTS_H_
