// System configuration validation (src/system-config.cpp and duct-tape/src/csr.c, compiled unchanged):
// the built-in defaults, which pushes are accepted, that a rejected push changes nothing, that the
// trust store path is never read past the buffer, and that a later push cannot relax csr-active-config.
#include <darlingserver/system-config.hpp>
#include <sys/csr.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static dserver_system_config_t emptyPush() {
	dserver_system_config_t config;
	std::memset(&config, 0, sizeof(config));
	config.version = DSERVER_SYSTEM_CONFIG_VERSION;
	config.size = sizeof(config);
	return config;
}

static dserver_system_config_t fullPush(uint32_t csr) {
	dserver_system_config_t config = emptyPush();
	config.present = DSERVER_SYSTEM_CONFIG_HAS_ALL;
	config.code_signing_policy = dserver_code_signing_policy_enforce;
	config.csr_active_config = csr;
	config.seal_images = 1;
	config.disable_pointer_authentication = 1;
	std::strcpy(config.trust_store_path, "/var/db/trust");
	return config;
}

static bool sameConfig(const dserver_system_config_t& a, const dserver_system_config_t& b) {
	return std::memcmp(&a, &b, sizeof(a)) == 0;
}

// applies `pushed` to a configuration that has `before` applied (or nothing, if null) and
// checks that it is rejected with `expected` without changing anything
static void checkRejected(const dserver_system_config_t* before, const dserver_system_config_t& pushed, int expected, const char* what) {
	SystemConfig config;
	bool isFirst = false;
	if (before) {
		config.apply(*before, isFirst);
	}
	auto old = config.current();
	isFirst = true;
	int code = config.apply(pushed, isFirst);
	if (code != expected) {
		std::printf("  got %d, expected %d\n", code, expected);
	}
	CHECK(code == expected && !isFirst && sameConfig(old, config.current()), what);
}

int main() {
	// defaults
	{
		SystemConfig config;
		auto current = config.current();
		CHECK(current.version == DSERVER_SYSTEM_CONFIG_VERSION && current.size == sizeof(current), "defaults: version and size filled in");
		CHECK(current.generation == 0 && current.present == 0, "defaults: generation 0, nothing present");
		CHECK(current.code_signing_policy == dserver_code_signing_policy_off && current.seal_images == 0, "defaults: no enforcement, no sealing");
		CHECK(current.csr_active_config == CSR_DISABLE_FLAGS, "defaults: csr-active-config is what `csrutil disable` sets");
		CHECK(current.trust_store_path[0] == '\0', "defaults: no trust store path");
		CHECK(current.disable_pointer_authentication == 0, "defaults: pointer authentication left on");
	}

	// a complete push
	{
		SystemConfig config;
		bool isFirst = false;
		auto pushed = fullPush(0);
		CHECK(config.apply(pushed, isFirst) == 0 && isFirst, "full push accepted as the first one");
		auto current = config.current();
		CHECK(current.generation == 1 && current.present == DSERVER_SYSTEM_CONFIG_HAS_ALL, "full push: generation 1, everything present");
		CHECK(current.code_signing_policy == dserver_code_signing_policy_enforce && current.csr_active_config == 0 && current.seal_images == 1, "full push: values in effect");
		CHECK(std::strcmp(current.trust_store_path, "/var/db/trust") == 0, "full push: trust store path in effect");
		CHECK(current.disable_pointer_authentication == 1, "full push: pointer authentication disable in effect");
	}

	// an empty push makes the defaults explicit and still counts as the first push
	{
		SystemConfig config;
		bool isFirst = false;
		CHECK(config.apply(emptyPush(), isFirst) == 0 && isFirst && config.current().generation == 1, "empty push accepted");
		CHECK(config.current().csr_active_config == CSR_DISABLE_FLAGS, "empty push: defaults in effect");
	}

	// malformed pushes
	{
		auto p = emptyPush();
		p.version = DSERVER_SYSTEM_CONFIG_VERSION + 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: unknown version");

		p = emptyPush();
		p.size = sizeof(p) - 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: wrong size");

		p = emptyPush();
		p.present = DSERVER_SYSTEM_CONFIG_HAS_ALL + 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: unknown present bit");

		p = emptyPush();
		p.generation = 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: nonzero generation");

		p = fullPush(0);
		p.code_signing_policy = dserver_code_signing_policy_enforce + 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: unknown code signing policy");

		p = fullPush(0);
		p.seal_images = 2;
		checkRejected(nullptr, p, -EINVAL, "rejected: seal_images not 0 or 1");

		p = fullPush(0);
		p.csr_active_config = ~(uint32_t)CSR_VALID_FLAGS;
		checkRejected(nullptr, p, -EINVAL, "rejected: csr flags outside CSR_VALID_FLAGS");

		p = emptyPush();
		p.code_signing_policy = dserver_code_signing_policy_warn;
		checkRejected(nullptr, p, -EINVAL, "rejected: code signing policy without its present bit");

		p = emptyPush();
		p.csr_active_config = CSR_ALLOW_UNRESTRICTED_FS;
		checkRejected(nullptr, p, -EINVAL, "rejected: csr-active-config without its present bit");

		p = emptyPush();
		p.seal_images = 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: seal_images without its present bit");

		p = fullPush(0);
		p.disable_pointer_authentication = 2;
		checkRejected(nullptr, p, -EINVAL, "rejected: disable_pointer_authentication not 0 or 1");

		p = emptyPush();
		p.disable_pointer_authentication = 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: disable_pointer_authentication without its present bit");

		p = fullPush(0);
		p.reserved = 1;
		checkRejected(nullptr, p, -EINVAL, "rejected: nonzero reserved field");

		p = emptyPush();
		p.trust_store_path[sizeof(p.trust_store_path) - 1] = 'x';
		checkRejected(nullptr, p, -EINVAL, "rejected: trust store path bytes without its present bit");

		p = fullPush(0);
		std::memset(p.trust_store_path, 'a', sizeof(p.trust_store_path));
		p.trust_store_path[0] = '/';
		checkRejected(nullptr, p, -EINVAL, "rejected: trust store path without a NUL inside the buffer");

		p = fullPush(0);
		std::strcpy(p.trust_store_path, "var/db/trust");
		checkRejected(nullptr, p, -EINVAL, "rejected: relative trust store path");

		p = fullPush(0);
		std::memset(p.trust_store_path, 0, sizeof(p.trust_store_path));
		checkRejected(nullptr, p, -EINVAL, "rejected: empty trust store path with its present bit");
	}

	// trust store path: the longest one fits, and nothing after the NUL is kept
	{
		SystemConfig config;
		bool isFirst = false;
		auto p = fullPush(0);
		std::memset(p.trust_store_path, 'a', sizeof(p.trust_store_path) - 1);
		p.trust_store_path[0] = '/';
		p.trust_store_path[sizeof(p.trust_store_path) - 1] = '\0';
		CHECK(config.apply(p, isFirst) == 0 && std::strlen(config.current().trust_store_path) == sizeof(p.trust_store_path) - 1, "longest trust store path accepted");

		SystemConfig config2;
		p = fullPush(0);
		std::strcpy(p.trust_store_path, "/a");
		p.trust_store_path[3] = 'z';
		auto current = (config2.apply(p, isFirst), config2.current());
		bool tailZero = true;
		for (size_t i = 2; i < sizeof(current.trust_store_path); ++i) {
			tailZero = tailZero && current.trust_store_path[i] == '\0';
		}
		CHECK(std::strcmp(current.trust_store_path, "/a") == 0 && tailZero, "bytes after the trust store path's NUL are dropped");
	}

	// csr-active-config after the first push: protections can be turned on, never off
	{
		auto first = fullPush(CSR_ALLOW_UNRESTRICTED_FS | CSR_ALLOW_TASK_FOR_PID);

		checkRejected(&first, fullPush(CSR_ALLOW_UNRESTRICTED_FS | CSR_ALLOW_TASK_FOR_PID | CSR_ALLOW_KERNEL_DEBUGGER), -EPERM, "later push may not set a new csr flag");
		checkRejected(&first, fullPush(CSR_ALLOW_KERNEL_DEBUGGER), -EPERM, "later push may not swap csr flags");

		auto noCsr = fullPush(0);
		noCsr.present &= ~DSERVER_SYSTEM_CONFIG_HAS_CSR_ACTIVE_CONFIG;
		noCsr.csr_active_config = 0;
		checkRejected(&first, noCsr, -EPERM, "later push may not fall back to the (relaxed) default");

		SystemConfig config;
		bool isFirst = false;
		config.apply(first, isFirst);
		CHECK(config.apply(first, isFirst) == 0 && !isFirst && config.current().generation == 2, "same csr flags accepted again");
		CHECK(config.apply(fullPush(CSR_ALLOW_TASK_FOR_PID), isFirst) == 0 && config.current().csr_active_config == CSR_ALLOW_TASK_FOR_PID, "later push may clear csr flags");
		auto relaxed = fullPush(CSR_ALLOW_TASK_FOR_PID);
		relaxed.code_signing_policy = dserver_code_signing_policy_off;
		CHECK(config.apply(relaxed, isFirst) == 0 && config.current().code_signing_policy == dserver_code_signing_policy_off, "later push may change the code signing policy");
		CHECK(config.apply(fullPush(CSR_ALLOW_UNRESTRICTED_FS | CSR_ALLOW_TASK_FOR_PID), isFirst) == -EPERM, "a cleared csr flag cannot come back");

		// the first push itself may be anything valid, including more relaxed than the default
		SystemConfig fresh;
		CHECK(fresh.apply(fullPush(CSR_VALID_FLAGS), isFirst) == 0 && isFirst, "first push may set any valid csr flags");
	}

	std::printf("%s\n", fails ? "FAILED" : "ALL PASSED");
	return fails ? 1 : 0;
}
