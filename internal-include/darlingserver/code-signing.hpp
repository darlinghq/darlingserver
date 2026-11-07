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

#ifndef _DARLINGSERVER_CODE_SIGNING_HPP_
#define _DARLINGSERVER_CODE_SIGNING_HPP_

#include <darlingserver/rpc-supplement.h>

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct dc_cs_image;

namespace DarlingServer {
	namespace CodeSigning {
		/**
		 * The result of verifying an image.
		 */
		struct Image {
			/**
			 * Everything about the image itself: status, signer, flags, the `DSERVER_CS_TRUST_STORE`
			 * bit, the CodeDirectory values and the entitlement lengths. The per-process fields
			 * (policy, csr configuration, generation, `DSERVER_CS_DENY_ATTACH`) are left zero.
			 */
			dserver_cs_state_t state;

			// the entitlements blobs, headers included (empty when there are none)
			std::vector<uint8_t> entitlements;
			std::vector<uint8_t> derEntitlements;

			// the entitlements set `com.apple.security.cs.disable-library-validation`
			bool disablesLibraryValidation = false;

			// for a certificate signature whose integrity was checked: the SHA-256 digest of the
			// signing certificate's public key (otherwise all zero)
			std::array<uint8_t, 32> signerKey{};

			// why the status is not valid; or, for a valid image, the problem that was tolerated
			// (see `Checks`); empty otherwise
			std::string error;

			Image();
		};

		// when checking integrity: images whose signed range is larger than this are not hashed, and are not valid
		constexpr uint64_t maxVerifiedSize = 256ull * 1024 * 1024;

		// limits on the parts that are read into memory whole
		constexpr uint64_t maxLoadCommandsSize = 16ull * 1024 * 1024;
		constexpr uint64_t maxSignatureSize = 16ull * 1024 * 1024;

		/**
		 * Says whether a CDHash is in Darling's trust store.
		 */
		using TrustCheck = std::function<bool(const uint8_t* cdhash)>;

		/**
		 * How much verifyImage checks, and what a problem with a signature costs.
		 */
		enum class Checks {
			// the code signing policy is `off`: only the signature is read. A signature that
			// cannot be fully parsed is still reported as valid, as signed code is on macOS.
			Signature,
			// `warn`: every code page and the CMS signature are checked too, but a problem only
			// sets `Image::error` (for the caller to log); the image is still reported as valid
			Report,
			// `enforce`: any problem makes the image invalid
			Enforce,
		};

		/**
		 * The checks a process's code signing policy asks for.
		 */
		Checks checksForPolicy(uint32_t policy);

		/**
		 * Reads the code signature of the image that starts at @p imageOffset in the regular file
		 * @p fd (a thin Mach-O file, or a slice of a universal one): what csops() reports about it.
		 * Malformed input never throws. An image that cannot be read as a Mach-O file is invalid;
		 * one without a signature is unsigned; for a signed one, see `Checks`.
		 *
		 * @param trusted May be empty, in which case nothing is trusted.
		 */
		Image verifyImage(int fd, uint64_t imageOffset, Checks checks, const TrustCheck& trusted);

		/**
		 * Checks the CMS signature of a parsed image: a detached signature by one signer over the
		 * primary CodeDirectory, whose signed attributes (when another CodeDirectory is the one
		 * used) also carry that CodeDirectory's digest. The certificate chain is not evaluated.
		 *
		 * @param signerKey Receives the SHA-256 digest of the signing certificate's public key.
		 * @returns 0, or -1 with @p error set.
		 */
		int verifyCms(const struct dc_cs_image& image, std::array<uint8_t, 32>& signerKey, std::string& error);

		/**
		 * The `CS_*` flags that `csops(CS_OPS_STATUS)` reports for a process started from a valid image.
		 */
		uint32_t statusFlags(const struct dc_cs_image& image, bool getTaskAllow, bool trusted);

		/**
		 * Whether a process may map @p library under library validation.
		 *
		 * @param main The process's state now (its flags may have changed since it started).
		 * @param mainImage The image the process registered.
		 */
		bool libraryValidationAllows(const dserver_cs_state_t& main, const Image& mainImage, const Image& library, std::string& error);

		/**
		 * The flags a `cs_update_flags` call may set and clear.
		 */
		uint32_t settableFlags();
		uint32_t clearableFlags();
	};
};

#endif // _DARLINGSERVER_CODE_SIGNING_HPP_
