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

// darlingserver's image verification, trust store and access rules (src/code-signing.cpp and
// src/trust-store.cpp, compiled unchanged) against the binaries in tests/fixtures/codesign,
// signed by `codesign` on macOS, and malformed variants of them.
// Usage: code_signing_test <fixture directory> <work directory> [<tool trust store> <tool public key>]
#include <darlingserver/code-signing.hpp>
#include <darlingserver/trust-store.hpp>
#include <darlingserver/dc_codesign.h>
#include <darlingserver/duct-tape/csr.h>

#include <kern/cs_blobs.h>

#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace DarlingServer;
using namespace DarlingServer::CodeSigning;

static int fails;
#define CHECK(c, what) do { bool ok_ = (c); printf("%s %s\n", ok_ ? "PASS" : "FAIL", std::string(what).c_str()); if (!ok_) fails++; } while (0)

static std::string fixtureDir;
static std::string workDir;

// <sys/csr.h>
static constexpr uint32_t testCsrAllowTaskForPid = 1u << 2;

static std::vector<uint8_t> readFile(const std::string& path) {
	std::ifstream file(path, std::ios::binary);
	if (!file) {
		fprintf(stderr, "cannot open %s\n", path.c_str());
		exit(2);
	}
	return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

static std::string writeWork(const std::string& name, const std::vector<uint8_t>& data) {
	std::string path = workDir + "/" + name;
	std::ofstream file(path, std::ios::binary | std::ios::trunc);
	file.write(reinterpret_cast<const char*>(data.data()), data.size());
	return path;
}

static Image verifyPath(const std::string& path, uint64_t offset = 0, const TrustCheck& trusted = {}, Checks checks = Checks::Enforce) {
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s\n", path.c_str());
		exit(2);
	}
	Image image = verifyImage(fd, offset, checks, trusted);
	close(fd);
	return image;
}

static Image verifyFixture(const std::string& name, uint64_t offset = 0, const TrustCheck& trusted = {}) {
	return verifyPath(fixtureDir + "/" + name, offset, trusted);
}

static std::string hex(const uint8_t* data, size_t length) {
	static const char digits[] = "0123456789abcdef";
	std::string out;
	for (size_t i = 0; i < length; ++i) {
		out += digits[data[i] >> 4];
		out += digits[data[i] & 15];
	}
	return out;
}

static void expectValid(const std::string& name, uint64_t offset, const char* cdhash, uint32_t flags, uint32_t signer, const char* identifier) {
	Image image = verifyFixture(name, offset);
	std::string label = name + "@" + std::to_string(offset);
	CHECK(image.state.status == dserver_cs_status_valid, label + ": valid (" + image.error + ")");
	CHECK(hex(image.state.cdhash, 20) == cdhash, label + ": CDHash " + hex(image.state.cdhash, 20));
	char flagText[16];
	snprintf(flagText, sizeof(flagText), "0x%08x", image.state.flags);
	CHECK(image.state.flags == flags, label + ": flags " + flagText);
	CHECK(image.state.signer == signer, label + ": signer");
	CHECK(strcmp(image.state.identifier, identifier) == 0, label + ": identifier " + image.state.identifier);
	CHECK(image.state.team_id[0] == '\0', label + ": no team ID");
	CHECK(image.state.image_offset == offset, label + ": image offset");
	CHECK(image.state.version == DSERVER_CS_STATE_VERSION && image.state.size == sizeof(dserver_cs_state_t), label + ": version and size");
}

static void testFixtures() {
	const uint32_t base = CS_SIGNED | CS_VALID | CS_DYLD_PLATFORM;
	// hardened runtime (and its implied flags) and get-task-allow; macOS reports 0x22011315 for this
	const uint32_t runtimeGta = base | CS_RUNTIME | CS_HARD | CS_KILL | CS_ENFORCEMENT | CS_FORCED_LV | CS_GET_TASK_ALLOW;

	expectValid("linker-signed", 0, "1e010f88a0f10df1da428fb53fad98a1637453ba", base | CS_LINKER_SIGNED, dserver_cs_signer_adhoc, "linker-signed");
	expectValid("adhoc", 0, "c3e41403df5753a157520767cbf90e56d9ffa33f", base, dserver_cs_signer_adhoc, "org.darlinghq.test.adhoc");
	expectValid("adhoc-runtime-ent", 0, "67316e6b715fa9eb830be17fe5e363126d0441db", runtimeGta, dserver_cs_signer_adhoc, "org.darlinghq.test.runtime");
	expectValid("fat-adhoc", 16384, "1744200c4dabb96a8f18824726f3468dbfb0c16c", base, dserver_cs_signer_adhoc, "org.darlinghq.test.fat");
	expectValid("fat-adhoc", 32768, "878f5e5d73364fd8b9787492260174038a011f6a", base, dserver_cs_signer_adhoc, "org.darlinghq.test.fat");
	expectValid("cms-signed", 0, "624f2b1e6c289dd7eae03f89ef5c22b6fa4dd077", base, dserver_cs_signer_certificate, "org.darlinghq.test.cms");
	expectValid("cms-dual", 0, "ab4845f2918045f80e0cf97f39d8e648536d489b", runtimeGta, dserver_cs_signer_certificate, "org.darlinghq.test.cmsdual");

	Image ent = verifyFixture("adhoc-runtime-ent");
	CHECK(ent.state.runtime_version != 0 && ent.state.hash_type == CS_HASHTYPE_SHA256, "adhoc-runtime-ent: runtime version and SHA-256 CodeDirectory used");
	CHECK(ent.entitlements.size() == ent.state.entitlements_length && ent.entitlements.size() > 8, "adhoc-runtime-ent: entitlements kept");
	CHECK(ent.entitlements.size() > 8 && ent.entitlements[0] == 0xfa && ent.entitlements[1] == 0xde && ent.entitlements[2] == 0x71 && ent.entitlements[3] == 0x71, "adhoc-runtime-ent: entitlements blob with its header");
	CHECK(ent.derEntitlements.size() == ent.state.der_entitlements_length, "adhoc-runtime-ent: DER entitlements length");
	CHECK(!ent.disablesLibraryValidation, "adhoc-runtime-ent: disable-library-validation is <false/>");

	Image cms1 = verifyFixture("cms-signed");
	Image cms2 = verifyFixture("cms-dual");
	CHECK((cms1.signerKey != std::array<uint8_t, 32>{}) && cms1.signerKey != cms2.signerKey, "cms fixtures: signed with two different keys");

	Image unsignedImage = verifyFixture("unsigned");
	CHECK(unsignedImage.state.status == dserver_cs_status_unsigned && unsignedImage.state.flags == 0, "unsigned: unsigned, no flags");

	Image fatHeader = verifyFixture("fat-adhoc", 0);
	CHECK(fatHeader.state.status == dserver_cs_status_invalid, "fat-adhoc@0: not an image (" + fatHeader.error + ")");
	Image fatMiddle = verifyFixture("fat-adhoc", 20000);
	CHECK(fatMiddle.state.status == dserver_cs_status_invalid, "fat-adhoc@20000: not a slice (" + fatMiddle.error + ")");

	// trust store hits become platform binaries
	Image trusted = verifyFixture("adhoc", 0, [](const uint8_t* cdhash) { return hex(cdhash, 20) == "c3e41403df5753a157520767cbf90e56d9ffa33f"; });
	CHECK((trusted.state.flags & CS_PLATFORM_BINARY) && (trusted.state.darling_flags & DSERVER_CS_TRUST_STORE), "adhoc in the trust store: CS_PLATFORM_BINARY");
	Image notTrusted = verifyFixture("adhoc", 0, [](const uint8_t*) { return false; });
	CHECK(!(notTrusted.state.flags & CS_PLATFORM_BINARY) && notTrusted.state.darling_flags == 0, "adhoc not in the trust store: no CS_PLATFORM_BINARY");
}

static void testQuirks() {
	// QUIRK: CS_ADHOC is not reported (see statusFlags in src/code-signing.cpp)
	Image adhoc = verifyFixture("adhoc");
	CHECK(adhoc.state.status == dserver_cs_status_valid && !(adhoc.state.flags & CS_ADHOC) && adhoc.state.flags == 0x22000001u,
		"quirk_status_flags_omit_adhoc: ad-hoc status 0x22000001 without CS_ADHOC (macOS 27.0.1)");

	// QUIRK: the hardened runtime adds CS_HARD, CS_KILL, CS_ENFORCEMENT and CS_FORCED_LV
	Image runtime = verifyFixture("adhoc-runtime-ent");
	CHECK(runtime.state.flags == 0x22011315u, "quirk_runtime_status_flags: runtime + get-task-allow status 0x22011315 (macOS 27.0.1)");
}

static size_t offsetIn(const uint8_t* pointer, const uint8_t* base) {
	return static_cast<size_t>(pointer - base);
}

static void testTampering() {
	std::vector<uint8_t> adhoc = readFile(fixtureDir + "/adhoc");
	char err[256];
	dc_cs_image image;

	// a byte of code
	{
		auto copy = adhoc;
		copy[0x4000 - 16] ^= 1; // inside the first page, after the load commands
		Image result = verifyPath(writeWork("code", copy));
		CHECK(result.state.status == dserver_cs_status_invalid && result.state.flags == 0, "tampered code page: invalid (" + result.error + ")");
		// without a policy, pages are not hashed: the signature is what csops() reports
		Image warned = verifyPath(workDir + "/code", 0, {}, Checks::Report);
		CHECK(warned.state.status == dserver_cs_status_valid && warned.state.flags == 0x22000001u && !warned.error.empty(),
			"tampered code page, warn: still valid, the problem reported (" + warned.error + ")");
		Image quick = verifyPath(workDir + "/code", 0, {}, Checks::Signature);
		CHECK(quick.state.status == dserver_cs_status_valid && hex(quick.state.cdhash, 20) == "c3e41403df5753a157520767cbf90e56d9ffa33f",
			"tampered code page, integrity not checked: the signature is still reported (" + quick.error + ")");
	}

	// a byte of the CMS signature
	{
		std::vector<uint8_t> cms = readFile(fixtureDir + "/cms-signed");
		if (dc_cs_parse(cms.data(), cms.size(), &image, err, sizeof(err)) != 0 || !image.cms) {
			CHECK(false, std::string("cms-signed parses: ") + err);
		} else {
			// the signature value ends the DER structure (codesign pads the blob with zeros after it)
			// structure (in BER, ending with end-of-contents octets)
			const unsigned char* end = image.cms;
			CMS_ContentInfo* decoded = d2i_CMS_ContentInfo(nullptr, &end, image.cms_length);
			size_t derLength = decoded ? static_cast<size_t>(end - image.cms) : 0;
			CMS_ContentInfo_free(decoded);
			CHECK(derLength > 64 && derLength <= image.cms_length, "cms-signed: the CMS blob decodes");
			size_t at = offsetIn(image.cms, cms.data()) + derLength - 40;
			cms[at] ^= 0x40;
			Image result = verifyPath(writeWork("cms", cms));
			CHECK(result.state.status == dserver_cs_status_invalid, "tampered CMS signature: invalid (" + result.error + ")");
			Image quick = verifyPath(workDir + "/cms", 0, {}, Checks::Signature);
			CHECK(quick.state.status == dserver_cs_status_valid && quick.state.signer == dserver_cs_signer_certificate && (quick.signerKey == std::array<uint8_t, 32>{}),
				"tampered CMS signature, integrity not checked: reported as signed, with no signing key (" + quick.error + ")");
		}
	}

	// the alternate (SHA-256) CodeDirectory of a dual signature: the CMS signature signs the SHA-1
	// one, and lists the digest of the other in its signed attributes
	{
		std::vector<uint8_t> dual = readFile(fixtureDir + "/cms-dual");
		if (dc_cs_parse(dual.data(), dual.size(), &image, err, sizeof(err)) != 0 || image.codedirectory->slot == CSSLOT_CODEDIRECTORY) {
			CHECK(false, std::string("cms-dual parses, with an alternate CodeDirectory in use: ") + err);
		} else {
			const uint8_t* cd = image.codedirectory->data;
			uint32_t identOffset = (cd[offsetof(CS_CodeDirectory, identOffset)] << 24) | (cd[offsetof(CS_CodeDirectory, identOffset) + 1] << 16) |
				(cd[offsetof(CS_CodeDirectory, identOffset) + 2] << 8) | cd[offsetof(CS_CodeDirectory, identOffset) + 3];
			size_t at = offsetIn(cd, dual.data()) + identOffset;
			dual[at] ^= 0x01;
			Image result = verifyPath(writeWork("dual", dual));
			CHECK(result.state.status == dserver_cs_status_invalid && result.error.find("CMS") != std::string::npos,
				"tampered alternate CodeDirectory: not covered by the CMS signature (" + result.error + ")");
		}
	}

	// a valid ad-hoc signature does not make a CMS one: drop the CMS blob's contents
	{
		std::vector<uint8_t> cms = readFile(fixtureDir + "/cms-signed");
		if (dc_cs_parse(cms.data(), cms.size(), &image, err, sizeof(err)) == 0 && image.cms) {
			memset(cms.data() + offsetIn(image.cms, cms.data()), 0, image.cms_length);
			Image result = verifyPath(writeWork("cms-zero", cms));
			CHECK(result.state.status == dserver_cs_status_invalid, "zeroed CMS signature: invalid (" + result.error + ")");
		}
	}

	// truncated
	{
		auto copy = adhoc;
		copy.resize(copy.size() - 100);
		Image result = verifyPath(writeWork("short", copy));
		CHECK(result.state.status == dserver_cs_status_invalid, "truncated file: invalid (" + result.error + ")");
	}

	// not regular files
	{
		Image none = verifyImage(-1, 0, Checks::Enforce, {});
		CHECK(none.state.status == dserver_cs_status_invalid, "no descriptor: invalid (" + none.error + ")");

		int pipes[2];
		if (pipe(pipes) == 0) {
			Image result = verifyImage(pipes[0], 0, Checks::Enforce, {});
			CHECK(result.state.status == dserver_cs_status_invalid, "a pipe: invalid, without blocking (" + result.error + ")");
			close(pipes[0]);
			close(pipes[1]);
		}

		int dir = open(workDir.c_str(), O_RDONLY | O_DIRECTORY);
		Image result = verifyImage(dir, 0, Checks::Enforce, {});
		CHECK(result.state.status == dserver_cs_status_invalid, "a directory: invalid (" + result.error + ")");
		close(dir);

		Image empty = verifyPath(writeWork("empty", {}));
		CHECK(empty.state.status == dserver_cs_status_invalid, "an empty file: invalid (" + empty.error + ")");
	}
}

static uint32_t readBE32(const uint8_t* p) {
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void writeBE32(uint8_t* p, uint32_t value) {
	p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value;
}

// a signature that cannot be fully parsed: without enforcement, csops must not report anything
// worse than for a valid signature (CS_SIGNED | CS_VALID); under enforcement, invalid
static void expectTolerated(const std::string& label, const std::vector<uint8_t>& file, bool mustFailUnderEnforce) {
	std::string path = writeWork("tolerated", file);
	const uint32_t validFlags = CS_SIGNED | CS_VALID | CS_DYLD_PLATFORM;

	Image off = verifyPath(path, 0, {}, Checks::Signature);
	CHECK(off.state.status == dserver_cs_status_valid && (off.state.flags & validFlags) == validFlags,
		label + ", policy off: reported as validly signed (" + off.error + ")");
	Image warned = verifyPath(path, 0, {}, Checks::Report);
	CHECK(warned.state.status == dserver_cs_status_valid && (warned.state.flags & validFlags) == validFlags,
		label + ", policy warn: reported as validly signed (" + warned.error + ")");
	if (mustFailUnderEnforce) {
		CHECK(!off.error.empty() && !warned.error.empty(), label + ": the problem is reported for logging");
		Image enforced = verifyPath(path, 0, {}, Checks::Enforce);
		CHECK(enforced.state.status == dserver_cs_status_invalid && enforced.state.flags == 0,
			label + ", policy enforce: invalid (" + enforced.error + ")");
	}
}

static void testUnparsableSignatures() {
	std::vector<uint8_t> adhoc = readFile(fixtureDir + "/adhoc");
	char err[256];
	dc_cs_image image;

	if (dc_cs_parse(adhoc.data(), adhoc.size(), &image, err, sizeof(err)) != 0) {
		CHECK(false, std::string("adhoc parses: ") + err);
		return;
	}
	size_t cd = offsetIn(image.codedirectory->data, adhoc.data());
	size_t superBlob = static_cast<size_t>(image.signature_offset);

	{
		auto copy = adhoc;
		writeBE32(copy.data() + cd + offsetof(CS_CodeDirectory, scatterOffset), 0x100);
		expectTolerated("a scatter list", copy, true);
	}
	{
		auto copy = adhoc;
		writeBE32(copy.data() + cd + offsetof(CS_CodeDirectory, version), 0x30000);
		expectTolerated("an unknown CodeDirectory version", copy, true);
	}
	{
		// the blob index entries follow the SuperBlob header (magic, length, count)
		auto copy = adhoc;
		uint32_t count = readBE32(copy.data() + superBlob + 8);
		for (uint32_t i = 0; i < count; ++i) {
			uint8_t* entry = copy.data() + superBlob + 12 + 8 * i;
			if (readBE32(entry) == CSSLOT_REQUIREMENTS) {
				writeBE32(entry, 0x7777);
			}
		}
		expectTolerated("an unknown blob type", copy, false);
	}
	{
		auto copy = adhoc;
		writeBE32(copy.data() + superBlob, 0x12345678);
		expectTolerated("a SuperBlob with the wrong magic", copy, true);
	}

	Image unsignedImage = verifyFixture("unsigned");
	Image unsignedOff = verifyPath(fixtureDir + "/unsigned", 0, {}, Checks::Signature);
	CHECK(unsignedImage.state.status == dserver_cs_status_unsigned && unsignedOff.state.status == dserver_cs_status_unsigned && unsignedOff.state.flags == 0,
		"an unsigned binary stays unsigned under every policy");
	CHECK(checksForPolicy(dserver_code_signing_policy_off) == Checks::Signature && checksForPolicy(dserver_code_signing_policy_warn) == Checks::Report &&
		checksForPolicy(dserver_code_signing_policy_enforce) == Checks::Enforce, "the checks follow the policy");
}

//
// trust store
//

static std::string ed25519PublicPem(EVP_PKEY* key) {
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, key);
	char* data = nullptr;
	long length = BIO_get_mem_data(bio, &data);
	std::string pem(data, static_cast<size_t>(length));
	BIO_free(bio);
	return pem;
}

static EVP_PKEY* newKey(int type) {
	EVP_PKEY* key = nullptr;
	EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(type, nullptr);
	EVP_PKEY_keygen_init(context);
	if (type == EVP_PKEY_RSA) {
		EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048);
	}
	EVP_PKEY_keygen(context, &key);
	EVP_PKEY_CTX_free(context);
	return key;
}

static void putLE(std::vector<uint8_t>& out, uint64_t value, int bytes) {
	for (int i = 0; i < bytes; ++i) {
		out.push_back(static_cast<uint8_t>(value >> (8 * i)));
	}
}

// writes a store the way tools/dc-trustcache.py does (independently of src/trust-store.cpp)
static std::vector<uint8_t> makeStore(EVP_PKEY* key, uint64_t generation, const std::vector<std::array<uint8_t, 20>>& cdhashes, const char* issuer = "darling-local", int signatureLength = 64) {
	std::vector<uint8_t> out;
	putLE(out, 0x44544331, 4);
	putLE(out, 1, 4);
	putLE(out, generation, 8);
	char issuerField[32] = {};
	strncpy(issuerField, issuer, sizeof(issuerField));
	out.insert(out.end(), issuerField, issuerField + 32);
	putLE(out, cdhashes.size(), 4);
	for (const auto& cdhash : cdhashes) {
		out.insert(out.end(), cdhash.begin(), cdhash.end());
		putLE(out, 1, 4);
	}

	uint8_t signature[64];
	size_t length = sizeof(signature);
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key);
	EVP_DigestSign(context, signature, &length, out.data(), out.size());
	EVP_MD_CTX_free(context);

	putLE(out, static_cast<uint64_t>(signatureLength), 4);
	out.insert(out.end(), signature, signature + length);
	return out;
}

static std::array<uint8_t, 20> cdhashOf(uint8_t first) {
	std::array<uint8_t, 20> cdhash{};
	cdhash[0] = first;
	cdhash[19] = 0x5a;
	return cdhash;
}

static bool parses(const std::vector<uint8_t>& store, const std::string& pem, TrustStore::Contents& contents, std::string& error) {
	return TrustStore::parse(store.data(), store.size(), reinterpret_cast<const uint8_t*>(pem.data()), pem.size(), contents, error);
}

static void testTrustStore(const char* toolStore, const char* toolPublicKey) {
	EVP_PKEY* key = newKey(EVP_PKEY_ED25519);
	EVP_PKEY* otherKey = newKey(EVP_PKEY_ED25519);
	EVP_PKEY* rsaKey = newKey(EVP_PKEY_RSA);
	std::string pem = ed25519PublicPem(key);
	TrustStore::Contents contents;
	std::string error;

	auto good = makeStore(key, 7, { cdhashOf(1), cdhashOf(2), cdhashOf(9) });
	CHECK(parses(good, pem, contents, error) && contents.generation == 7 && contents.cdhashes.size() == 3 && contents.cdhashes[2] == cdhashOf(9), "trust store: a valid store parses");

	auto empty = makeStore(key, 1, {});
	CHECK(parses(empty, pem, contents, error) && contents.cdhashes.empty(), "trust store: an empty store parses");

	CHECK(!parses(good, ed25519PublicPem(otherKey), contents, error) && contents.cdhashes.empty(), "trust store: another key does not verify (" + error + ")");
	CHECK(!parses(good, ed25519PublicPem(rsaKey), contents, error), "trust store: an RSA key is refused (" + error + ")");
	CHECK(!parses(good, "not a key", contents, error), "trust store: garbage key is refused (" + error + ")");

	auto flipped = good;
	flipped[52] ^= 1; // the first CDHash
	CHECK(!parses(flipped, pem, contents, error), "trust store: a changed entry does not verify (" + error + ")");

	auto badSignature = good;
	badSignature.back() ^= 1;
	CHECK(!parses(badSignature, pem, contents, error), "trust store: a changed signature does not verify (" + error + ")");

	CHECK(!parses(makeStore(key, 1, { cdhashOf(2), cdhashOf(1) }), pem, contents, error), "trust store: unsorted entries are refused (" + error + ")");
	CHECK(!parses(makeStore(key, 1, { cdhashOf(2), cdhashOf(2) }), pem, contents, error), "trust store: duplicate entries are refused (" + error + ")");
	CHECK(!parses(makeStore(key, 1, { cdhashOf(1) }, "apple"), pem, contents, error), "trust store: another issuer is refused (" + error + ")");
	CHECK(!parses(makeStore(key, 1, { cdhashOf(1) }, "darling-local", 65), pem, contents, error), "trust store: a wrong signature length is refused (" + error + ")");

	auto truncated = good;
	truncated.resize(truncated.size() - 1);
	CHECK(!parses(truncated, pem, contents, error), "trust store: truncated (" + error + ")");
	auto extended = good;
	extended.push_back(0);
	CHECK(!parses(extended, pem, contents, error), "trust store: trailing data (" + error + ")");
	auto countTooBig = good;
	countTooBig[48] = 0xff; countTooBig[49] = 0xff; countTooBig[50] = 0xff; countTooBig[51] = 0xff;
	CHECK(!parses(countTooBig, pem, contents, error), "trust store: an impossible entry count (" + error + ")");
	CHECK(!parses(std::vector<uint8_t>(10), pem, contents, error), "trust store: a tiny file (" + error + ")");

	// what tools/dc-trustcache.py writes
	if (toolStore && toolPublicKey) {
		auto store = readFile(toolStore);
		auto toolPem = readFile(toolPublicKey);
		error.clear();
		bool ok = TrustStore::parse(store.data(), store.size(), toolPem.data(), toolPem.size(), contents, error);
		CHECK(ok && contents.generation == 2 && contents.cdhashes.size() == 2 &&
			hex(contents.cdhashes[0].data(), 20) == "1e010f88a0f10df1da428fb53fad98a1637453ba" &&
			hex(contents.cdhashes[1].data(), 20) == "c3e41403df5753a157520767cbf90e56d9ffa33f",
			"trust store: tools/dc-trustcache.py's store parses (" + error + ")");
	} else {
		printf("SKIP trust store written by tools/dc-trustcache.py (no python3 or openssl)\n");
	}

	// opening inside the prefix
	std::string prefix = workDir + "/prefix";
	mkdir(prefix.c_str(), 0755);
	mkdir((prefix + "/private").c_str(), 0755);
	writeWork("outside", good);
	writeWork("prefix/private/store", good);
	symlink("/outside", (prefix + "/private/absolute-link").c_str());
	symlink("../../outside", (prefix + "/private/relative-link").c_str());
	symlink((workDir + "/outside").c_str(), (prefix + "/private/host-link").c_str());

	int root = open(prefix.c_str(), O_PATH | O_DIRECTORY);
	int fd = TrustStore::openBeneath(root, "/private/store", error);
	CHECK(fd >= 0, "trust store path: opens inside the prefix (" + error + ")");
	if (fd >= 0) close(fd);
	CHECK(TrustStore::openBeneath(root, "/private/../private/store", error) < 0 && !error.empty(), "trust store path: `..` refused (" + error + ")");
	CHECK(TrustStore::openBeneath(root, "private/store", error) < 0 && !error.empty(), "trust store path: a relative path refused (" + error + ")");
	CHECK(TrustStore::openBeneath(root, "/private/absolute-link", error) < 0, "trust store path: an absolute symlink resolves inside the prefix (not found)");
	CHECK(TrustStore::openBeneath(root, "/private/relative-link", error) < 0, "trust store path: a relative symlink cannot climb out of the prefix");
	CHECK(TrustStore::openBeneath(root, "/private/host-link", error) < 0, "trust store path: a symlink to the host path stays inside the prefix");
	CHECK(TrustStore::openBeneath(root, "/private/missing", error) < 0 && error.empty(), "trust store path: a missing store is not an error");
	close(root);

	// the public key must be out of darlingserver's reach
	std::string keyPath = workDir + "/key.pem";
	{
		std::ofstream file(keyPath);
		file << pem;
	}
	CHECK(!TrustStore::isProtected(keyPath, error), "trust store key: a key darlingserver's user owns is not used (" + error + ")");
	if (geteuid() != 0) {
		CHECK(TrustStore::isProtected("/etc/hostname", error) || access("/etc/hostname", F_OK) != 0, "trust store key: a root-owned file in root-owned directories is protected (" + error + ")");
	}
	TrustStore store;
	CHECK(!store.contains(prefix, "/private/store", keyPath, cdhashOf(1).data(), error) && !error.empty(), "trust store: not used with an unprotected key (" + error + ")");
	CHECK(!store.contains(prefix, "/private/missing", keyPath, cdhashOf(1).data(), error) && error.empty(), "trust store: no store, no error");

	EVP_PKEY_free(key);
	EVP_PKEY_free(otherKey);
	EVP_PKEY_free(rsaKey);
}

//
// access rules
//

static dserver_cs_state_t stateWith(uint32_t flags, uint32_t policy = dserver_code_signing_policy_enforce, uint32_t darlingFlags = 0) {
	dserver_cs_state_t state{};
	state.version = DSERVER_CS_STATE_VERSION;
	state.size = sizeof(state);
	state.status = dserver_cs_status_valid;
	state.flags = flags;
	state.darling_flags = darlingFlags;
	state.code_signing_policy = policy;
	return state;
}

static void testTaskPortRules() {
	const uint32_t sipOn = 0;
	const uint32_t sipAllowsTfp = testCsrAllowTaskForPid;
	CHECK(dtape_csr_allows_task_for_pid(sipAllowsTfp) && !dtape_csr_allows_task_for_pid(sipOn), "CSR_ALLOW_TASK_FOR_PID matches <sys/csr.h>");

	auto plain = stateWith(CS_SIGNED | CS_VALID);
	auto gta = stateWith(CS_SIGNED | CS_VALID | CS_GET_TASK_ALLOW);
	auto hardened = stateWith(CS_SIGNED | CS_VALID | CS_RUNTIME);
	auto hardenedGta = stateWith(CS_SIGNED | CS_VALID | CS_RUNTIME | CS_GET_TASK_ALLOW);
	auto platform = stateWith(CS_SIGNED | CS_VALID | CS_PLATFORM_BINARY);
	auto unsignedState = stateWith(0);

	struct Row {
		const char* what;
		bool self;
		uint32_t caller;
		uint32_t target;
		const dserver_cs_state_t* state;
		PortFlavor flavor;
		uint32_t csr;
		bool expected;
	} rows[] = {
		{ "self, control", true, 501, 501, &hardened, PortFlavor::Control, sipOn, true },
		{ "same user, name", false, 501, 501, &hardened, PortFlavor::Name, sipOn, true },
		{ "same user, inspect", false, 501, 501, &hardened, PortFlavor::Inspect, sipOn, true },
		{ "other user, name", false, 502, 501, &plain, PortFlavor::Name, sipOn, false },
		{ "other user, inspect", false, 502, 501, &plain, PortFlavor::Inspect, sipOn, false },
		{ "root, inspect of another user", false, 0, 501, &plain, PortFlavor::Inspect, sipOn, true },
		{ "same user, control, no get-task-allow", false, 501, 501, &plain, PortFlavor::Control, sipOn, false },
		{ "same user, read, no get-task-allow", false, 501, 501, &plain, PortFlavor::Read, sipOn, false },
		{ "same user, control, unsigned", false, 501, 501, &unsignedState, PortFlavor::Control, sipOn, false },
		{ "same user, control, get-task-allow", false, 501, 501, &gta, PortFlavor::Control, sipOn, true },
		{ "same user, read, get-task-allow", false, 501, 501, &gta, PortFlavor::Read, sipOn, true },
		{ "same user, control, hardened + get-task-allow", false, 501, 501, &hardenedGta, PortFlavor::Control, sipOn, true },
		{ "other user, control, get-task-allow", false, 502, 501, &gta, PortFlavor::Control, sipOn, false },
		{ "root, control, get-task-allow", false, 0, 501, &gta, PortFlavor::Control, sipOn, true },
		{ "root, control, plain", false, 0, 501, &plain, PortFlavor::Control, sipOn, true },
		{ "root, control, unsigned", false, 0, 501, &unsignedState, PortFlavor::Control, sipOn, true },
		{ "root, control, hardened, SIP on", false, 0, 501, &hardened, PortFlavor::Control, sipOn, false },
		{ "root, read, hardened, SIP on", false, 0, 501, &hardened, PortFlavor::Read, sipOn, false },
		{ "root, control, platform, SIP on", false, 0, 0, &platform, PortFlavor::Control, sipOn, false },
		{ "root, control, hardened, SIP allows task_for_pid", false, 0, 501, &hardened, PortFlavor::Control, sipAllowsTfp, true },
		{ "root, control, platform, SIP allows task_for_pid", false, 0, 0, &platform, PortFlavor::Control, sipAllowsTfp, true },
		{ "same user, control, hardened, SIP allows task_for_pid", false, 501, 501, &hardened, PortFlavor::Control, sipAllowsTfp, false },
	};

	for (const auto& row : rows) {
		CHECK(taskPortRule(row.self, row.caller, row.target, *row.state, row.flavor, row.csr) == row.expected, std::string("task port rule: ") + row.what);
	}

	auto denied = stateWith(CS_SIGNED | CS_VALID | CS_GET_TASK_ALLOW, dserver_code_signing_policy_enforce, DSERVER_CS_DENY_ATTACH);
	CHECK(attachRule(false, 501, 501, gta, sipOn), "attach rule: same user, get-task-allow");
	CHECK(!attachRule(false, 501, 501, plain, sipOn), "attach rule: same user, no get-task-allow");
	CHECK(!attachRule(false, 501, 501, denied, sipOn), "attach rule: deny-attach wins over get-task-allow");
	CHECK(!attachRule(false, 0, 501, denied, sipAllowsTfp), "attach rule: deny-attach wins over root and SIP");
	CHECK(!attachRule(true, 501, 501, denied, sipOn), "attach rule: deny-attach also refuses being traced at its own request");

	CHECK(applyPolicy(dserver_code_signing_policy_off, false) == Verdict::Allowed, "policy off: nothing is denied");
	CHECK(applyPolicy(dserver_code_signing_policy_warn, false) == Verdict::WouldDeny, "policy warn: allowed, with a warning");
	CHECK(applyPolicy(dserver_code_signing_policy_enforce, false) == Verdict::Denied, "policy enforce: denied");
	CHECK(applyPolicy(dserver_code_signing_policy_enforce, true) == Verdict::Allowed, "policy enforce: allowed when the rule allows");
	CHECK(applyPolicy(7, false) == Verdict::WouldDeny, "unknown policy: not enforced");
}

static void testLibraryValidation() {
	std::string error;
	Image hardenedMain = verifyFixture("adhoc-runtime-ent"); // CS_FORCED_LV
	Image plainMain = verifyFixture("adhoc");
	Image library = verifyFixture("adhoc");
	Image cmsLibrary = verifyFixture("cms-signed");
	Image unsignedLibrary = verifyFixture("unsigned");
	Image trustedLibrary = verifyFixture("adhoc", 0, [](const uint8_t*) { return true; });

	CHECK(libraryValidationAllows(plainMain.state, plainMain, unsignedLibrary, error), "library validation off: anything loads");
	CHECK(!libraryValidationAllows(hardenedMain.state, hardenedMain, library, error), "library validation: an ad-hoc library is refused (" + error + ")");
	CHECK(!libraryValidationAllows(hardenedMain.state, hardenedMain, unsignedLibrary, error), "library validation: an unsigned library is refused (" + error + ")");
	CHECK(libraryValidationAllows(hardenedMain.state, hardenedMain, trustedLibrary, error), "library validation: a platform library loads");

	auto requireLv = plainMain.state;
	requireLv.flags |= CS_REQUIRE_LV;
	CHECK(!libraryValidationAllows(requireLv, plainMain, library, error), "library validation: CS_REQUIRE_LV set later applies");

	Image disabling = hardenedMain;
	disabling.disablesLibraryValidation = true;
	CHECK(libraryValidationAllows(disabling.state, disabling, library, error), "library validation: disable-library-validation entitlement");

	// the same team: only with the same signing key
	Image teamMain = verifyFixture("cms-dual");
	Image teamLibrary = cmsLibrary;
	strcpy(teamMain.state.team_id, "DTESTTEAM1");
	strcpy(teamLibrary.state.team_id, "DTESTTEAM1");
	CHECK(!libraryValidationAllows(teamMain.state, teamMain, teamLibrary, error), "library validation: same team ID, different signing key is refused");
	teamLibrary.signerKey = teamMain.signerKey;
	CHECK(libraryValidationAllows(teamMain.state, teamMain, teamLibrary, error), "library validation: same team ID and signing key loads");
	strcpy(teamLibrary.state.team_id, "OTHERTEAM1");
	CHECK(!libraryValidationAllows(teamMain.state, teamMain, teamLibrary, error), "library validation: another team is refused");
	Image adhocTeam = library;
	strcpy(adhocTeam.state.team_id, "DTESTTEAM1");
	adhocTeam.signerKey = teamMain.signerKey;
	CHECK(!libraryValidationAllows(teamMain.state, teamMain, adhocTeam, error), "library validation: an ad-hoc library claiming the team is refused");
	Image unverifiedMain = teamMain;
	Image unverifiedLibrary = teamLibrary;
	strcpy(unverifiedLibrary.state.team_id, "DTESTTEAM1");
	unverifiedMain.signerKey = {};
	unverifiedLibrary.signerKey = {};
	CHECK(!libraryValidationAllows(unverifiedMain.state, unverifiedMain, unverifiedLibrary, error), "library validation: the same team without checked signing keys is refused");
}

static void testFlagRules() {
	CHECK((settableFlags() & (CS_VALID | CS_GET_TASK_ALLOW | CS_PLATFORM_BINARY | CS_INSTALLER | CS_DEBUGGED)) == 0, "cs_update_flags: privileges cannot be set");
	CHECK((clearableFlags() & (CS_HARD | CS_KILL | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_FORCED_LV)) == 0, "cs_update_flags: restrictions cannot be cleared");
	CHECK((settableFlags() & CS_HARD) && (settableFlags() & CS_KILL) && (clearableFlags() & CS_VALID), "cs_update_flags: CS_OPS_MARKHARD, MARKKILL and MARKINVALID are possible");
}

int main(int argc, char** argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s <fixture directory> <work directory> [<tool store> <tool public key>]\n", argv[0]);
		return 2;
	}
	fixtureDir = argv[1];
	workDir = argv[2];

	testFixtures();
	testQuirks();
	testTampering();
	testUnparsableSignatures();
	testTrustStore(argc > 4 ? argv[3] : nullptr, argc > 4 ? argv[4] : nullptr);
	testTaskPortRules();
	testLibraryValidation();
	testFlagRules();

	printf("%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
