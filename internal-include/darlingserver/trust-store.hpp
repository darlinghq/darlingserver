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

#ifndef _DARLINGSERVER_TRUST_STORE_HPP_
#define _DARLINGSERVER_TRUST_STORE_HPP_

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace DarlingServer {
	/**
	 * Darling's trust store: a list of CDHashes whose code counts as part of the platform
	 * (`CS_PLATFORM_BINARY`). It is Darling's own format, not Apple's trust cache, written by
	 * `tools/dc-trustcache.py`; all integers are little-endian:
	 *
	 *   offset  size
	 *        0     4  magic 0x44544331 ("DTC1")
	 *        4     4  version (1)
	 *        8     8  generation (incremented by the tool on each change)
	 *       16    32  issuer, "darling-local" padded with NULs
	 *       48     4  number of entries
	 *       52  24*n  entries: a CDHash (20 bytes) and a flags word, which is not used
	 *                 (the tool writes 1); in strictly ascending order of CDHash
	 *              4  signature length (64)
	 *             64  an Ed25519 signature over everything before the signature length
	 *
	 * The store lives inside the prefix (by default `/private/var/db/darling/trustcache`, or the
	 * `TrustStorePath` setting) and is opened without leaving the prefix. The public key comes from
	 * the Darling installation (`LIBEXEC_PATH/private/var/db/darling/trustcache.pub`), not from the
	 * prefix, and is only used when darlingserver itself could not change it (see `isProtected`):
	 * then nothing running in the prefix through the Darwin APIs can add a CDHash, even as root.
	 */
	class TrustStore {
	public:
		using CDHash = std::array<uint8_t, 20>;

		struct Contents {
			uint64_t generation = 0;
			std::vector<CDHash> cdhashes; // ascending
		};

		static constexpr size_t headerSize = 52;
		static constexpr size_t entrySize = 24;
		static constexpr size_t signatureSize = 64;
		static constexpr uint32_t maxEntries = 1u << 20;
		static constexpr size_t maxPublicKeySize = 4096;

		/**
		 * Checks a store against a PEM-encoded Ed25519 public key and decodes it.
		 */
		static bool parse(const uint8_t* data, size_t size, const uint8_t* publicKeyPem, size_t publicKeyPemSize, Contents& contents, std::string& error);

		/**
		 * Whether darlingserver's own credentials can neither write nor replace the file at @p path:
		 * neither it nor any directory above it is owned by darlingserver's effective user or
		 * writable by it.
		 */
		static bool isProtected(const std::string& path, std::string& error);

		/**
		 * Opens @p guestPath (absolute, without `..` components) inside the directory @p rootFd as
		 * if that were the root, never leaving it, even through symbolic links.
		 *
		 * @returns A descriptor, or -1 with @p error set.
		 */
		static int openBeneath(int rootFd, const std::string& guestPath, std::string& error);

		/**
		 * Whether @p cdhash is in the store at @p storeGuestPath inside @p prefix, verified with
		 * the key at @p publicKeyPath. The store is read again only when the store or key file has
		 * changed.
		 *
		 * @param error Set when the store could not be used; empty when it does not exist.
		 */
		bool contains(const std::string& prefix, const std::string& storeGuestPath, const std::string& publicKeyPath, const uint8_t* cdhash, std::string& error);

		static TrustStore& sharedInstance();

	private:
		std::mutex _mutex;
		bool _cached = false;
		std::array<uint64_t, 12> _cachedIdentity{};
		bool _cachedValid = false;
		std::string _cachedError;
		Contents _contents;
	};
};

#endif // _DARLINGSERVER_TRUST_STORE_HPP_
