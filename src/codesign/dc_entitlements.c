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

#include <darlingserver/dc_entitlements.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_parser(void) {
	// makes the parser safe to use from several threads at once
	xmlInitParser();
}

// skips the nodes that carry no data between elements: comments, processing instructions and whitespace
static xmlNode* next_element(xmlNode* node) {
	while (node && (node->type == XML_COMMENT_NODE || node->type == XML_PI_NODE || (node->type == XML_TEXT_NODE && xmlIsBlankNode(node)))) {
		node = node->next;
	}
	return node;
}

static bool is_element(const xmlNode* node, const char* name) {
	return node && node->type == XML_ELEMENT_NODE && !node->ns && xmlStrEqual(node->name, (const xmlChar*)name);
}

static bool is_plist_value(const xmlNode* node) {
	static const char* const names[] = { "true", "false", "string", "data", "date", "integer", "real", "array", "dict" };

	for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i) {
		if (is_element(node, names[i])) {
			return true;
		}
	}
	return false;
}

// `<true/>` and `<false/>` have no attributes and no content
static bool is_empty_element(const xmlNode* node) {
	return !node->properties && !node->children;
}

// a `<key>` has no attributes and only text
static bool is_valid_key(const xmlNode* node) {
	if (node->properties) {
		return false;
	}
	for (const xmlNode* child = node->children; child; child = child->next) {
		if (child->type != XML_TEXT_NODE && child->type != XML_CDATA_SECTION_NODE) {
			return false;
		}
	}
	return true;
}

static int compare_names(const void* a, const void* b) {
	return strcmp(*(const char* const*)a, *(const char* const*)b);
}

static int lookup(xmlDoc* document, const char* const* keys, size_t key_count, enum dc_cs_entitlement_value* values) {
	// a DOCTYPE naming the plist DTD is normal; anything that declares entities is not accepted
	if (document->extSubset || (document->intSubset && (document->intSubset->entities || document->intSubset->pentities))) {
		return -1;
	}

	xmlNode* plist = xmlDocGetRootElement(document);
	if (!is_element(plist, "plist") || next_element(plist->next)) {
		return -1;
	}

	xmlNode* dict = next_element(plist->children);
	if (!is_element(dict, "dict") || next_element(dict->next)) {
		return -1;
	}

	// at most one key per two child nodes
	size_t capacity = 0;
	for (xmlNode* child = dict->children; child; child = child->next) {
		++capacity;
	}

	char** names = calloc(capacity / 2 + 1, sizeof(*names));
	size_t name_count = 0;
	int result = 0;

	if (!names) {
		return -1;
	}

	for (xmlNode* entry = next_element(dict->children); entry;) {
		if (!is_element(entry, "key") || !is_valid_key(entry)) {
			result = -1;
			break;
		}

		xmlNode* value = next_element(entry->next);
		if (!is_plist_value(value)) {
			result = -1;
			break;
		}

		enum dc_cs_entitlement_value kind = DC_CS_ENTITLEMENT_OTHER;
		if (is_element(value, "true") || is_element(value, "false")) {
			if (!is_empty_element(value)) {
				result = -1;
				break;
			}
			kind = is_element(value, "true") ? DC_CS_ENTITLEMENT_TRUE : DC_CS_ENTITLEMENT_FALSE;
		}

		xmlChar* name = xmlNodeGetContent(entry);
		if (!name || name_count >= capacity / 2 + 1) {
			xmlFree(name);
			result = -1;
			break;
		}
		names[name_count++] = (char*)name;

		for (size_t i = 0; i < key_count; ++i) {
			if (keys[i] && xmlStrEqual(name, (const xmlChar*)keys[i])) {
				values[i] = kind;
			}
		}

		entry = next_element(value->next);
	}

	// a key that appears twice could mean different things to different readers
	if (result == 0 && name_count > 1) {
		qsort(names, name_count, sizeof(*names), compare_names);
		for (size_t i = 1; i < name_count; ++i) {
			if (strcmp(names[i - 1], names[i]) == 0) {
				result = -1;
				break;
			}
		}
	}

	for (size_t i = 0; i < name_count; ++i) {
		xmlFree(names[i]);
	}
	free(names);

	return result;
}

int dc_cs_entitlements_lookup(const uint8_t* xml, size_t length, const char* const* keys, size_t key_count, enum dc_cs_entitlement_value* values) {
	if (!values || (key_count > 0 && !keys)) {
		return -1;
	}

	for (size_t i = 0; i < key_count; ++i) {
		values[i] = DC_CS_ENTITLEMENT_ABSENT;
	}

	if (!xml) {
		return -1;
	}

	while (length > 0 && xml[length - 1] == '\0') {
		--length;
	}
	if (length == 0 || length > DC_CS_ENTITLEMENTS_MAX) {
		return -1;
	}

	pthread_once(&init_once, init_parser);

	// no XML_PARSE_NOENT (entity substitution) and no XML_PARSE_DTDLOAD (external DTDs); keep libxml2's size limits
	xmlDoc* document = xmlReadMemory((const char*)xml, (int)length, "entitlements.plist", NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if (!document) {
		return -1;
	}

	int result = lookup(document, keys, key_count, values);
	xmlFreeDoc(document);

	if (result != 0) {
		for (size_t i = 0; i < key_count; ++i) {
			values[i] = DC_CS_ENTITLEMENT_ABSENT;
		}
	}

	return result;
}
