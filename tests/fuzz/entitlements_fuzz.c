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

// libFuzzer target for the entitlements plist reader. See tests/run-fuzz.sh.
#include <darlingserver/dc_entitlements.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	static const char* const keys[] = {
		"com.apple.security.get-task-allow",
		"com.apple.security.cs.disable-library-validation",
		"a",
	};
	enum dc_cs_entitlement_value values[3];

	if (dc_cs_entitlements_lookup(data, size, keys, 3, values) != 0) {
		for (int i = 0; i < 3; ++i) {
			if (values[i] != DC_CS_ENTITLEMENT_ABSENT) {
				__builtin_trap();
			}
		}
	}
	return 0;
}
