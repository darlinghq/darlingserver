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

#ifndef _DARLINGSERVER_PLATFORM_IDENTITY_HPP_
#define _DARLINGSERVER_PLATFORM_IDENTITY_HPP_

#include <darlingserver/rpc-supplement.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>

namespace DarlingServer {
	/**
	 * The platform identity pushed by the guest configuration daemon (see `dserver_platform_identity_t`),
	 * and the defaults used for the keys it leaves out.
	 *
	 * This class only derives, validates and stores the values; checking who may push is up to the caller.
	 */
	class PlatformIdentity {
	public:
		static constexpr size_t machineIDSize = 16;
		static constexpr size_t uuidSize = 16;

	private:
		mutable std::mutex _mutex;
		dserver_platform_identity_t _defaults;
		dserver_platform_identity_t _identity;

	public:
		/**
		 * Starts out with the defaults (generation 0).
		 *
		 * @param machineID The host's 16-byte machine ID, or `nullptr` if the host has none.
		 *                  Only values derived from it are kept.
		 */
		explicit PlatformIdentity(const uint8_t* machineID);

		PlatformIdentity(const PlatformIdentity&) = delete;
		PlatformIdentity& operator=(const PlatformIdentity&) = delete;

		/**
		 * The instance for the host's machine ID (`/etc/machine-id`).
		 */
		static PlatformIdentity& sharedInstance();

		/**
		 * Parses the contents of a machine-id(5) file: 32 hexadecimal digits, optionally followed by a newline.
		 * An all-zero ID is rejected.
		 */
		static bool parseMachineID(const char* text, size_t length, uint8_t machineID[machineIDSize]);

		/**
		 * Reads and parses a machine-id(5) file.
		 */
		static bool readMachineID(const char* path, uint8_t machineID[machineIDSize]);

		/**
		 * Derives the default platform UUID and serial number from a machine ID (see rpc-supplement.h).
		 *
		 * @returns `false` if the derivation failed; @p uuid and @p serial are then left unchanged.
		 */
		static bool deriveIdentifiers(const uint8_t machineID[machineIDSize], uint8_t uuid[uuidSize], char serial[DSERVER_PLATFORM_IDENTITY_STRING_MAX]);

		/**
		 * Checks a pushed identity without applying it.
		 *
		 * @returns 0 if it is well-formed, or `-EINVAL`.
		 */
		int validate(const dserver_platform_identity_t& pushed) const;

		/**
		 * Validates @p pushed and, if it is acceptable, makes it the identity in effect.
		 * Nothing is changed when the push is rejected.
		 *
		 * @param onApply If set, called with the new identity while it is being put into effect,
		 *                so that pushes are passed on in the order they were applied.
		 * @returns 0 or `-EINVAL`.
		 */
		int apply(const dserver_platform_identity_t& pushed, const std::function<void(const dserver_platform_identity_t&)>& onApply = nullptr);

		/**
		 * A copy of the identity in effect, with `generation` filled in.
		 */
		dserver_platform_identity_t current() const;
	};
};

#endif // _DARLINGSERVER_PLATFORM_IDENTITY_HPP_
