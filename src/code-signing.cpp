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

#include <darlingserver/code-signing.hpp>
#include <darlingserver/dc_codesign.h>
#include <darlingserver/dc_entitlements.h>
#include <darlingserver/duct-tape/csr.h>

#include <kern/cs_blobs.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>

static_assert(DSERVER_CS_CDHASH_LEN == DC_CS_CDHASH_LEN, "must match the parser");
static_assert(DSERVER_CS_TEAM_ID_MAX == DC_CS_TEAM_ID_MAX, "must match the parser");
static_assert(DSERVER_CS_IDENTIFIER_MAX == DC_CS_IDENTIFIER_MAX, "must match the parser");
static_assert(offsetof(dserver_cs_state_t, generation) == 56, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_cs_state_t, cdhash) == 104, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_cs_state_t, team_id) == 128, "the layout must not depend on the architecture");
static_assert(sizeof(dserver_cs_state_t) == 128 + DSERVER_CS_TEAM_ID_MAX + DSERVER_CS_IDENTIFIER_MAX, "the layout must not depend on the architecture");

// the signed CMS attribute that lists the digest of every CodeDirectory, each as a SEQUENCE of
// the digest algorithm and the digest (seen in the CMS signatures `codesign` writes; see the
// cms-dual fixture)
static constexpr const char* codeDirectoryDigestsAttribute = "1.2.840.113635.100.9.2";

// the entitlements that are looked up
static constexpr const char* getTaskAllowEntitlement = "com.apple.security.get-task-allow";
static constexpr const char* disableLibraryValidationEntitlement = "com.apple.security.cs.disable-library-validation";

DarlingServer::CodeSigning::Image::Image() {
	memset(&state, 0, sizeof(state));
	state.version = DSERVER_CS_STATE_VERSION;
	state.size = sizeof(state);
};

namespace {
	template<typename T, void (*Free)(T*)>
	struct Deleter {
		void operator()(T* object) const {
			Free(object);
		}
	};

	using CmsPointer = std::unique_ptr<CMS_ContentInfo, Deleter<CMS_ContentInfo, CMS_ContentInfo_free>>;
	using BioPointer = std::unique_ptr<BIO, Deleter<BIO, BIO_free_all>>;
	using ObjectPointer = std::unique_ptr<ASN1_OBJECT, Deleter<ASN1_OBJECT, ASN1_OBJECT_free>>;

	void freeTypes(STACK_OF(ASN1_TYPE)* types) {
		sk_ASN1_TYPE_pop_free(types, ASN1_TYPE_free);
	};

	void freeCertificates(STACK_OF(X509)* certificates) {
		sk_X509_free(certificates);
	};

	using TypesPointer = std::unique_ptr<STACK_OF(ASN1_TYPE), Deleter<STACK_OF(ASN1_TYPE), freeTypes>>;
	using CertificatesPointer = std::unique_ptr<STACK_OF(X509), Deleter<STACK_OF(X509), freeCertificates>>;

	// reads exactly `length` bytes at `offset`
	bool readAt(int fd, uint64_t offset, void* buffer, size_t length) {
		auto out = static_cast<uint8_t*>(buffer);
		size_t done = 0;

		while (done < length) {
			ssize_t result = pread(fd, out + done, length - done, static_cast<off_t>(offset + done));
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

	int digestNid(uint8_t hashType) {
		switch (hashType) {
			case CS_HASHTYPE_SHA1:   return NID_sha1;
			case CS_HASHTYPE_SHA256: return NID_sha256;
			case CS_HASHTYPE_SHA384: return NID_sha384;
			default:                 return NID_undef;
		}
	};

	// whether the signed attribute that lists CodeDirectory digests lists `codeDirectory`
	bool cmsListsCodeDirectory(CMS_SignerInfo* signer, const struct dc_cs_codedirectory& codeDirectory) {
		ObjectPointer oid(OBJ_txt2obj(codeDirectoryDigestsAttribute, 1));
		int nid = digestNid(codeDirectory.hash_type);

		if (!oid || nid == NID_undef) {
			return false;
		}

		int index = CMS_signed_get_attr_by_OBJ(signer, oid.get(), -1);
		if (index < 0) {
			return false;
		}

		X509_ATTRIBUTE* attribute = CMS_signed_get_attr(signer, index);
		int count = attribute ? X509_ATTRIBUTE_count(attribute) : 0;

		for (int i = 0; i < count; ++i) {
			ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attribute, i);
			if (!value || value->type != V_ASN1_SEQUENCE || !value->value.sequence) {
				continue;
			}

			const unsigned char* data = value->value.sequence->data;
			TypesPointer elements(d2i_ASN1_SEQUENCE_ANY(nullptr, &data, value->value.sequence->length));
			if (!elements || sk_ASN1_TYPE_num(elements.get()) != 2) {
				continue;
			}

			ASN1_TYPE* algorithm = sk_ASN1_TYPE_value(elements.get(), 0);
			ASN1_TYPE* digest = sk_ASN1_TYPE_value(elements.get(), 1);
			if (algorithm->type != V_ASN1_OBJECT || digest->type != V_ASN1_OCTET_STRING) {
				continue;
			}

			if (OBJ_obj2nid(algorithm->value.object) == nid &&
				static_cast<size_t>(ASN1_STRING_length(digest->value.octet_string)) == codeDirectory.digest_length &&
				memcmp(ASN1_STRING_get0_data(digest->value.octet_string), codeDirectory.digest, codeDirectory.digest_length) == 0)
			{
				return true;
			}
		}

		return false;
	};

	void copyString(char* destination, size_t size, const char* source) {
		size_t length = strnlen(source, size - 1);
		memcpy(destination, source, length);
		destination[length] = '\0';
	};
};

int DarlingServer::CodeSigning::verifyCms(const struct dc_cs_image& image, std::array<uint8_t, 32>& signerKey, std::string& error) {
	const struct dc_cs_codedirectory* primary = nullptr;

	for (uint32_t i = 0; i < image.codedirectory_count; ++i) {
		if (image.codedirectories[i].slot == CSSLOT_CODEDIRECTORY) {
			primary = &image.codedirectories[i];
		}
	}

	if (!primary || !image.codedirectory) {
		error = "there is no primary CodeDirectory for the CMS signature to sign";
		return -1;
	}
	if (!image.cms || image.cms_length == 0) {
		error = "there is no CMS signature";
		return -1;
	}

	// `codesign` pads the blob with zeros after the DER structure
	const unsigned char* data = image.cms;
	CmsPointer cms(d2i_CMS_ContentInfo(nullptr, &data, image.cms_length));
	if (!cms) {
		error = "the CMS signature cannot be decoded";
		return -1;
	}

	if (OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed || CMS_is_detached(cms.get()) != 1) {
		error = "the CMS signature is not detached signed data";
		return -1;
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms.get());
	if (!signers || sk_CMS_SignerInfo_num(signers) != 1) {
		error = "the CMS signature does not have exactly one signer";
		return -1;
	}

	BioPointer content(BIO_new_mem_buf(primary->data, static_cast<int>(primary->length)));
	if (!content) {
		error = "out of memory";
		return -1;
	}

	// checks the signature over the signed attributes and their message digest of the content;
	// there are no trust anchors to evaluate the certificate chain against
	if (CMS_verify(cms.get(), nullptr, nullptr, content.get(), nullptr, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1) {
		error = "the CMS signature does not verify";
		return -1;
	}

	// the CMS signature signs the primary CodeDirectory only; another one that is used instead
	// must be listed in the signed attributes
	if (image.codedirectory != primary && !cmsListsCodeDirectory(sk_CMS_SignerInfo_value(signers, 0), *image.codedirectory)) {
		error = "the CMS signature does not cover the CodeDirectory that is used";
		return -1;
	}

	CertificatesPointer certificates(CMS_get0_signers(cms.get()));
	if (!certificates || sk_X509_num(certificates.get()) != 1) {
		error = "the signing certificate is missing";
		return -1;
	}

	X509_PUBKEY* publicKey = X509_get_X509_PUBKEY(sk_X509_value(certificates.get(), 0));
	unsigned char* encoded = nullptr;
	int encodedLength = publicKey ? i2d_X509_PUBKEY(publicKey, &encoded) : -1;
	unsigned int digestLength = 0;
	bool hashed = encodedLength > 0 && EVP_Digest(encoded, static_cast<size_t>(encodedLength), signerKey.data(), &digestLength, EVP_sha256(), nullptr) == 1 && digestLength == signerKey.size();
	OPENSSL_free(encoded);
	if (!hashed) {
		error = "cannot hash the signing certificate's public key";
		return -1;
	}

	return 0;
};

uint32_t DarlingServer::CodeSigning::statusFlags(const struct dc_cs_image& image, bool getTaskAllow, bool trusted) {
	// QUIRK: a running process does not report CS_ADHOC in its status, even when its signature
	// is ad-hoc; the other CodeDirectory flags in CS_ALLOWED_MACHO (e.g. CS_RUNTIME, CS_HARD,
	// CS_KILL, CS_LINKER_SIGNED) are reported.
	// Not documented. Evidence: black-box observation, csops(getpid(), CS_OPS_STATUS) in programs
	// signed with `codesign -s -` (with and without `-o runtime`, `-o kill,hard`, get-task-allow)
	// and linker-signed, on macOS 27.0.1, arm64 natively and x86_64 under Rosetta (tier 2).
	// Test: quirk_status_flags_omit_adhoc in tests/host/code_signing_test.cpp.
	uint32_t flags = CS_SIGNED | CS_VALID | (image.cd_flags & CS_ALLOWED_MACHO & ~static_cast<uint32_t>(CS_ADHOC));

	if (image.cd_flags & CS_RUNTIME) {
		// QUIRK: a process with the hardened runtime also reports CS_HARD, CS_KILL, CS_ENFORCEMENT
		// and CS_FORCED_LV (library validation; documented as part of the hardened runtime, the
		// flag values are not).
		// Evidence: the same black-box observation as above; status 0x22011311 for an ad-hoc
		// `-o runtime` signature on both architectures (tier 2).
		// Test: quirk_runtime_status_flags in tests/host/code_signing_test.cpp.
		flags |= CS_HARD | CS_KILL | CS_ENFORCEMENT | CS_FORCED_LV;
	}

	if (getTaskAllow) {
		flags |= CS_GET_TASK_ALLOW;
	}

	// <kern/cs_blobs.h>: the dyld that loaded the process is a platform binary. Darling's dyld is
	// part of the Darling installation, and every validly signed process observed on macOS
	// reports this flag (same black-box observation as above).
	flags |= CS_DYLD_PLATFORM;

	// the trust store plays the part of the platform's trust cache: what it lists is a platform binary
	if (trusted) {
		flags |= CS_PLATFORM_BINARY;
	}

	return flags;
};

DarlingServer::CodeSigning::Checks DarlingServer::CodeSigning::checksForPolicy(uint32_t policy) {
	switch (policy) {
		case dserver_code_signing_policy_off:     return Checks::Signature;
		case dserver_code_signing_policy_enforce: return Checks::Enforce;
		default:                                  return Checks::Report;
	}
};

DarlingServer::CodeSigning::Image DarlingServer::CodeSigning::verifyImage(int fd, uint64_t imageOffset, Checks checks, const TrustCheck& trusted) {
	Image result;
	struct stat st;
	char err[256] = "";
	struct dc_cs_image image;
	bool checkIntegrity = (checks != Checks::Signature);

	result.state.status = dserver_cs_status_invalid;
	result.state.image_offset = imageOffset;

	// the image is signed, but something about the signature is wrong
	auto signatureProblem = [&](const std::string& reason) {
		result.error = reason;
		if (checks != Checks::Enforce) {
			// without enforcement, signed code is not reported as anything worse than validly
			// signed code; only what is certain is filled in
			result.state.status = dserver_cs_status_valid;
			result.state.signer = dserver_cs_signer_adhoc;
			result.state.flags = CS_SIGNED | CS_VALID | CS_DYLD_PLATFORM;
		}
		return result;
	};

	if (fd < 0) {
		result.error = "the image could not be opened";
		return result;
	}

	// a regular file only: anything else could block or never end
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		result.error = "the image is not a regular file";
		return result;
	}

	uint64_t fileSize = static_cast<uint64_t>(st.st_size);
	uint64_t imageSize = 0;

	{
		uint8_t head[DC_CS_FAT_HEADER_MAX];
		size_t headLength = fileSize < sizeof(head) ? static_cast<size_t>(fileSize) : sizeof(head);
		if (!readAt(fd, 0, head, headLength)) {
			result.error = "cannot read the file header";
			return result;
		}
		if (dc_cs_image_at(head, headLength, fileSize, imageOffset, &imageSize, err, sizeof(err)) != 0) {
			result.error = err;
			return result;
		}
	}

	uint64_t headerLength = 0;
	{
		uint8_t head[DC_CS_MACHO_HEADER_MAX];
		size_t headLength = imageSize < sizeof(head) ? static_cast<size_t>(imageSize) : sizeof(head);
		if (!readAt(fd, imageOffset, head, headLength)) {
			result.error = "cannot read the Mach-O header";
			return result;
		}
		if (dc_cs_header_length(head, headLength, imageSize, &headerLength, err, sizeof(err)) != 0) {
			result.error = err;
			return result;
		}
	}

	if (headerLength > maxLoadCommandsSize) {
		result.error = "the load commands are too large";
		return result;
	}

	// `image` points into these two buffers
	std::vector<uint8_t> header(static_cast<size_t>(headerLength));
	std::vector<uint8_t> signature;

	if (!readAt(fd, imageOffset, header.data(), header.size())) {
		result.error = "cannot read the load commands";
		return result;
	}

	int located = dc_cs_locate(header.data(), header.size(), imageSize, &image, err, sizeof(err));
	if (located == DC_CS_UNSIGNED) {
		result.state.status = dserver_cs_status_unsigned;
		return result;
	} else if (located != 0) {
		return signatureProblem(err);
	}

	if (image.signature_size > maxSignatureSize) {
		return signatureProblem("the signature is too large");
	}

	signature.resize(image.signature_size);
	if (!readAt(fd, imageOffset + image.signature_offset, signature.data(), signature.size())) {
		return signatureProblem("cannot read the signature");
	}

	if (dc_cs_parse_signature(signature.data(), signature.size(), &image, err, sizeof(err)) != 0) {
		return signatureProblem(err);
	}

	// problems with the signed contents; fatal only under enforcement
	std::string problem;

	if (checkIntegrity && image.code_limit > maxVerifiedSize) {
		problem = "the image is too large to verify";
		checkIntegrity = false;
	}

	if (checkIntegrity) {
		std::vector<uint8_t> page(static_cast<size_t>(1) << image.page_size_log2);
		uint64_t pageSize = page.size();

		for (uint32_t i = 0; i < image.code_slot_count && problem.empty(); ++i) {
			size_t length = static_cast<size_t>(dc_cs_page_length(&image, i));
			if (!readAt(fd, imageOffset + i * pageSize, page.data(), length)) {
				problem = "cannot read code page " + std::to_string(i);
			} else if (dc_cs_verify_page(&image, i, page.data(), length) != 0) {
				problem = "code page " + std::to_string(i) + " does not match its hash";
			}
		}
	}

	if (image.cms && image.cms_length > 0) {
		std::string cmsProblem;
		if (checkIntegrity && verifyCms(image, result.signerKey, cmsProblem) != 0) {
			result.signerKey = {};
			if (problem.empty()) {
				problem = cmsProblem;
			}
		}
		result.state.signer = dserver_cs_signer_certificate;
	} else {
		result.state.signer = dserver_cs_signer_adhoc;
	}

	if (!problem.empty() && checks == Checks::Enforce) {
		result.state.signer = dserver_cs_signer_none;
		result.error = problem;
		return result;
	}
	result.error = problem;

	bool getTaskAllow = false;
	if (image.entitlements) {
		static const char* const keys[] = { getTaskAllowEntitlement, disableLibraryValidationEntitlement };
		enum dc_cs_entitlement_value values[2];

		// a malformed document grants nothing; the blob is still bound to the signature, so it is kept
		if (dc_cs_entitlements_lookup(image.entitlements + 8, image.entitlements_length - 8, keys, 2, values) == 0) {
			getTaskAllow = (values[0] == DC_CS_ENTITLEMENT_TRUE);
			result.disablesLibraryValidation = (values[1] == DC_CS_ENTITLEMENT_TRUE);
		}

		result.entitlements.assign(image.entitlements, image.entitlements + image.entitlements_length);
	}
	if (image.der_entitlements) {
		result.derEntitlements.assign(image.der_entitlements, image.der_entitlements + image.der_entitlements_length);
	}

	bool isTrusted = trusted && trusted(image.cdhash);

	result.state.status = dserver_cs_status_valid;
	result.state.flags = statusFlags(image, getTaskAllow, isTrusted);
	result.state.darling_flags = isTrusted ? DSERVER_CS_TRUST_STORE : 0;
	result.state.hash_type = image.hash_type;
	result.state.platform = image.platform;
	result.state.runtime_version = image.runtime_version;
	result.state.entitlements_length = static_cast<uint32_t>(result.entitlements.size());
	result.state.der_entitlements_length = static_cast<uint32_t>(result.derEntitlements.size());
	result.state.code_limit = image.code_limit;
	result.state.exec_seg_base = image.exec_seg_base;
	result.state.exec_seg_limit = image.exec_seg_limit;
	result.state.exec_seg_flags = image.exec_seg_flags;
	memcpy(result.state.cdhash, image.cdhash, sizeof(result.state.cdhash));
	copyString(result.state.team_id, sizeof(result.state.team_id), image.team_id);
	copyString(result.state.identifier, sizeof(result.state.identifier), image.identifier);

	return result;
};

bool DarlingServer::CodeSigning::libraryValidationAllows(const dserver_cs_state_t& main, const Image& mainImage, const Image& library, std::string& error) {
	// the hardened runtime turns library validation on (CS_FORCED_LV), as can the signature or
	// the process itself (CS_REQUIRE_LV); the documented entitlement turns it off again
	if ((main.flags & (CS_REQUIRE_LV | CS_FORCED_LV)) == 0 || mainImage.disablesLibraryValidation) {
		return true;
	}

	if (library.state.status != dserver_cs_status_valid) {
		error = "the library is not validly signed";
		return false;
	}

	if (library.state.flags & CS_PLATFORM_BINARY) {
		return true;
	}

	// the same team. Without Apple's trust anchors, a team ID is only as good as the
	// certificate that signs it, so both must also be signed with the same certificate key.
	if (main.signer == dserver_cs_signer_certificate && library.state.signer == dserver_cs_signer_certificate &&
		main.team_id[0] != '\0' && strncmp(main.team_id, library.state.team_id, sizeof(main.team_id)) == 0 &&
		mainImage.signerKey != std::array<uint8_t, 32>{} && mainImage.signerKey == library.signerKey)
	{
		return true;
	}

	error = "the library is neither a platform binary nor signed by the same team";
	return false;
};

bool DarlingServer::CodeSigning::taskPortRule(bool isSelf, uint32_t callerUid, uint32_t targetUid, const dserver_cs_state_t& target, PortFlavor flavor, uint32_t csrActiveConfig) {
	// a process always has its own task port
	if (isSelf) {
		return true;
	}

	bool root = (callerUid == 0);
	bool sameUser = (callerUid == targetUid);

	switch (flavor) {
		case PortFlavor::Name:
		case PortFlavor::Inspect:
			return root || sameUser;

		case PortFlavor::Read:
		case PortFlavor::Control:
		default:
			// a target that allows debugging can be debugged by its own user and by root
			if ((target.flags & CS_GET_TASK_ALLOW) && (root || sameUser)) {
				return true;
			}

			// otherwise only root, and with System Integrity Protection on, not for hardened or platform processes
			if (root) {
				bool protectedTarget = (target.flags & (CS_RUNTIME | CS_PLATFORM_BINARY)) != 0;
				return !protectedTarget || dtape_csr_allows_task_for_pid(csrActiveConfig);
			}

			return false;
	}
};

bool DarlingServer::CodeSigning::attachRule(bool isSelf, uint32_t callerUid, uint32_t targetUid, const dserver_cs_state_t& target, uint32_t csrActiveConfig) {
	if (target.darling_flags & DSERVER_CS_DENY_ATTACH) {
		return false;
	}

	return taskPortRule(isSelf, callerUid, targetUid, target, PortFlavor::Control, csrActiveConfig);
};

DarlingServer::CodeSigning::Verdict DarlingServer::CodeSigning::applyPolicy(uint32_t targetPolicy, bool ruleAllows) {
	if (ruleAllows || targetPolicy == dserver_code_signing_policy_off) {
		return Verdict::Allowed;
	}

	return (targetPolicy == dserver_code_signing_policy_enforce) ? Verdict::Denied : Verdict::WouldDeny;
};

uint32_t DarlingServer::CodeSigning::settableFlags() {
	// what CS_OPS_MARKHARD, CS_OPS_MARKKILL, CS_OPS_MARKRESTRICT and CS_OPS_SET_STATUS may add:
	// flags that only make a process more restricted
	return CS_HARD | CS_KILL | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_EXEC_SET_HARD | CS_EXEC_SET_KILL | CS_EXEC_SET_ENFORCEMENT;
};

uint32_t DarlingServer::CodeSigning::clearableFlags() {
	// what CS_OPS_MARKINVALID and CS_OPS_CLEARINSTALLER may remove: validity and privileges.
	// Clearing library validation (CS_OPS_CLEAR_LV) needs an entitlement and is not offered.
	return CS_VALID | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_EXEC_INHERIT_SIP;
};
