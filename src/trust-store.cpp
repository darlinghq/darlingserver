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

#include <darlingserver/trust-store.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <memory>

static constexpr uint32_t storeMagic = 0x44544331;
static constexpr uint32_t storeVersion = 1;
static constexpr char storeIssuer[32] = "darling-local";

namespace {
	struct FileDescriptor {
		int fd;
		explicit FileDescriptor(int fd): fd(fd) {};
		~FileDescriptor() {
			if (fd >= 0) {
				close(fd);
			}
		};
		FileDescriptor(const FileDescriptor&) = delete;
		FileDescriptor& operator=(const FileDescriptor&) = delete;
	};

	uint32_t readLE32(const uint8_t* p) {
		return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
	};

	uint64_t readLE64(const uint8_t* p) {
		return static_cast<uint64_t>(readLE32(p)) | (static_cast<uint64_t>(readLE32(p + 4)) << 32);
	};

	bool readAll(int fd, std::vector<uint8_t>& data, size_t size) {
		data.resize(size);
		size_t done = 0;
		while (done < size) {
			ssize_t result = pread(fd, data.data() + done, size - done, static_cast<off_t>(done));
			if (result < 0 && errno == EINTR) {
				continue;
			}
			if (result <= 0) {
				return false;
			}
			done += static_cast<size_t>(result);
		}
		return true;
	};

	void identityOf(const struct stat& st, uint64_t* out) {
		out[0] = st.st_dev;
		out[1] = st.st_ino;
		out[2] = static_cast<uint64_t>(st.st_size);
		out[3] = static_cast<uint64_t>(st.st_mtim.tv_sec) * 1000000000ull + static_cast<uint64_t>(st.st_mtim.tv_nsec);
		out[4] = static_cast<uint64_t>(st.st_ctim.tv_sec) * 1000000000ull + static_cast<uint64_t>(st.st_ctim.tv_nsec);
		out[5] = st.st_mode;
	};
};

bool DarlingServer::TrustStore::parse(const uint8_t* data, size_t size, const uint8_t* publicKeyPem, size_t publicKeyPemSize, Contents& contents, std::string& error) {
	contents = Contents();

	if (size < headerSize + 4 + signatureSize) {
		error = "the trust store is truncated";
		return false;
	}
	if (readLE32(data) != storeMagic || readLE32(data + 4) != storeVersion) {
		error = "the trust store has the wrong magic or version";
		return false;
	}
	if (memcmp(data + 16, storeIssuer, sizeof(storeIssuer)) != 0) {
		error = "the trust store is not issued by darling-local";
		return false;
	}

	uint64_t generation = readLE64(data + 8);
	uint32_t count = readLE32(data + 48);
	if (count > maxEntries || size != headerSize + static_cast<size_t>(count) * entrySize + 4 + signatureSize) {
		error = "the trust store's size does not match its number of entries";
		return false;
	}

	size_t signedLength = headerSize + static_cast<size_t>(count) * entrySize;
	if (readLE32(data + signedLength) != signatureSize) {
		error = "the trust store's signature has the wrong length";
		return false;
	}

	if (!publicKeyPem || publicKeyPemSize == 0 || publicKeyPemSize > maxPublicKeySize) {
		error = "no usable public key";
		return false;
	}

	std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(publicKeyPem, static_cast<int>(publicKeyPemSize)), BIO_free);
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(bio ? PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr) : nullptr, EVP_PKEY_free);
	if (!key || EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519) {
		error = "the public key is not an Ed25519 key";
		return false;
	}

	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
		EVP_DigestVerify(context.get(), data + signedLength + 4, signatureSize, data, signedLength) != 1)
	{
		error = "the trust store's signature does not verify";
		return false;
	}

	contents.generation = generation;
	contents.cdhashes.resize(count);
	for (uint32_t i = 0; i < count; ++i) {
		memcpy(contents.cdhashes[i].data(), data + headerSize + static_cast<size_t>(i) * entrySize, 20);
		if (i > 0 && !(contents.cdhashes[i - 1] < contents.cdhashes[i])) {
			contents = Contents();
			error = "the trust store's entries are not in strictly ascending order";
			return false;
		}
	}

	return true;
};

bool DarlingServer::TrustStore::isProtected(const std::string& path, std::string& error) {
	char resolved[PATH_MAX];

	if (!realpath(path.c_str(), resolved)) {
		error = "cannot resolve " + path + ": " + strerror(errno);
		return false;
	}

	std::string current = resolved;
	uid_t self = geteuid();

	while (true) {
		struct stat st;
		if (stat(current.c_str(), &st) != 0) {
			error = "cannot examine " + current + ": " + strerror(errno);
			return false;
		}
		if (st.st_uid == self || faccessat(AT_FDCWD, current.c_str(), W_OK, AT_EACCESS) == 0) {
			error = current + " can be changed by darlingserver's own user, so it cannot protect the trust store";
			return false;
		}
		if (current == "/") {
			break;
		}
		auto slash = current.find_last_of('/');
		current = (slash == 0) ? "/" : current.substr(0, slash);
	}

	return true;
};

int DarlingServer::TrustStore::openBeneath(int rootFd, const std::string& guestPath, std::string& error) {
	if (guestPath.empty() || guestPath[0] != '/') {
		error = "the trust store path must be absolute";
		return -1;
	}

	// RESOLVE_IN_ROOT would keep `..` inside the prefix anyway; refuse it outright
	size_t start = 0;
	while (start < guestPath.size()) {
		size_t end = guestPath.find('/', start);
		if (end == std::string::npos) {
			end = guestPath.size();
		}
		if (guestPath.compare(start, end - start, "..") == 0) {
			error = "the trust store path must not contain `..`";
			return -1;
		}
		start = end + 1;
	}

	struct open_how how;
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
	how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;

	int fd = static_cast<int>(syscall(SYS_openat2, rootFd, guestPath.c_str(), &how, sizeof(how)));
	if (fd < 0) {
		int code = errno;
		error = (code == ENOENT) ? "" : std::string("cannot open the trust store: ") + strerror(code);
		errno = code;
		return -1;
	}

	return fd;
};

bool DarlingServer::TrustStore::contains(const std::string& prefix, const std::string& storeGuestPath, const std::string& publicKeyPath, const uint8_t* cdhash, std::string& error) {
	std::unique_lock lock(_mutex);
	error.clear();

	FileDescriptor root(open(prefix.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC));
	struct stat keyStat;
	struct stat storeStat;

	if (root.fd < 0) {
		error = "cannot open the prefix";
		return false;
	}

	// no store (the usual case) is not an error
	FileDescriptor store(openBeneath(root.fd, storeGuestPath, error));
	if (store.fd < 0) {
		return false;
	}

	if (!isProtected(publicKeyPath, error)) {
		return false;
	}

	FileDescriptor key(open(publicKeyPath.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
	if (key.fd < 0 || fstat(key.fd, &keyStat) != 0 || !S_ISREG(keyStat.st_mode) || keyStat.st_size <= 0 || static_cast<size_t>(keyStat.st_size) > maxPublicKeySize) {
		error = "cannot read the trust store's public key " + publicKeyPath;
		return false;
	}

	size_t largest = headerSize + static_cast<size_t>(maxEntries) * entrySize + 4 + signatureSize;
	if (fstat(store.fd, &storeStat) != 0 || !S_ISREG(storeStat.st_mode) || storeStat.st_size <= 0 || static_cast<size_t>(storeStat.st_size) > largest) {
		error = "the trust store is not a regular file of a valid size";
		return false;
	}

	std::array<uint64_t, 12> identity{};
	identityOf(keyStat, identity.data());
	identityOf(storeStat, identity.data() + 6);

	if (!_cached || identity != _cachedIdentity) {
		std::vector<uint8_t> keyData;
		std::vector<uint8_t> storeData;
		Contents contents;
		std::string parseError;
		bool valid = false;

		if (!readAll(key.fd, keyData, static_cast<size_t>(keyStat.st_size)) || !readAll(store.fd, storeData, static_cast<size_t>(storeStat.st_size))) {
			parseError = "cannot read the trust store";
		} else {
			valid = parse(storeData.data(), storeData.size(), keyData.data(), keyData.size(), contents, parseError);
		}

		_cached = true;
		_cachedIdentity = identity;
		_cachedValid = valid;
		_cachedError = parseError;
		_contents = valid ? std::move(contents) : Contents();
	}

	if (!_cachedValid) {
		error = _cachedError;
		return false;
	}

	CDHash wanted;
	memcpy(wanted.data(), cdhash, wanted.size());
	return std::binary_search(_contents.cdhashes.begin(), _contents.cdhashes.end(), wanted);
};

DarlingServer::TrustStore& DarlingServer::TrustStore::sharedInstance() {
	static TrustStore instance;
	return instance;
};
