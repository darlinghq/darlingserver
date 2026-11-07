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

#include <darlingserver/system-config.hpp>
#include <darlingserver/duct-tape/csr.h>

#include <cerrno>
#include <cstddef>
#include <cstring>

static_assert(offsetof(dserver_system_config_t, generation) == 24, "the layout must not depend on the architecture");
static_assert(offsetof(dserver_system_config_t, trust_store_path) == 32, "the layout must not depend on the architecture");
static_assert(sizeof(dserver_system_config_t) == 32 + DSERVER_SYSTEM_CONFIG_PATH_MAX, "the layout must not depend on the architecture");

static bool allZero(const char* bytes, size_t length) {
	for (size_t i = 0; i < length; ++i) {
		if (bytes[i] != 0) {
			return false;
		}
	}
	return true;
};

static dserver_system_config_t defaultConfig() {
	dserver_system_config_t config;
	memset(&config, 0, sizeof(config));
	config.version = DSERVER_SYSTEM_CONFIG_VERSION;
	config.size = sizeof(config);
	config.present = 0;
	config.code_signing_policy = dserver_code_signing_policy_off;
	config.csr_active_config = dtape_csr_default_config();
	config.seal_images = 0;
	config.generation = 0;
	return config;
};

DarlingServer::SystemConfig::SystemConfig():
	_config(defaultConfig())
	{};

DarlingServer::SystemConfig& DarlingServer::SystemConfig::sharedInstance() {
	static SystemConfig instance;
	return instance;
};

int DarlingServer::SystemConfig::validate(const dserver_system_config_t& pushed) {
	if (pushed.version != DSERVER_SYSTEM_CONFIG_VERSION || pushed.size != sizeof(dserver_system_config_t)) {
		return -EINVAL;
	}

	if ((pushed.present & ~DSERVER_SYSTEM_CONFIG_HAS_ALL) != 0 || pushed.generation != 0) {
		return -EINVAL;
	}

	// a value that was not pushed must be zero, so that a daemon bug that fills in a value
	// but forgets its `present` bit does not go unnoticed
	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_CODE_SIGNING_POLICY) {
		if (pushed.code_signing_policy > dserver_code_signing_policy_enforce) {
			return -EINVAL;
		}
	} else if (pushed.code_signing_policy != 0) {
		return -EINVAL;
	}

	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_CSR_ACTIVE_CONFIG) {
		if (!dtape_csr_config_is_valid(pushed.csr_active_config)) {
			return -EINVAL;
		}
	} else if (pushed.csr_active_config != 0) {
		return -EINVAL;
	}

	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_SEAL_IMAGES) {
		if (pushed.seal_images > 1) {
			return -EINVAL;
		}
	} else if (pushed.seal_images != 0) {
		return -EINVAL;
	}

	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_TRUST_STORE_PATH) {
		// the terminating NUL must be inside the buffer; nothing past it is looked at
		const void* nul = memchr(pushed.trust_store_path, '\0', sizeof(pushed.trust_store_path));
		if (!nul || pushed.trust_store_path[0] != '/') {
			return -EINVAL;
		}
	} else if (!allZero(pushed.trust_store_path, sizeof(pushed.trust_store_path))) {
		return -EINVAL;
	}

	return 0;
};

int DarlingServer::SystemConfig::apply(const dserver_system_config_t& pushed, bool& isFirst) {
	isFirst = false;

	int code = validate(pushed);
	if (code != 0) {
		return code;
	}

	// build the new configuration from the defaults and the values that were pushed
	dserver_system_config_t next = defaultConfig();
	next.present = pushed.present;
	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_CODE_SIGNING_POLICY) {
		next.code_signing_policy = pushed.code_signing_policy;
	}
	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_CSR_ACTIVE_CONFIG) {
		next.csr_active_config = pushed.csr_active_config;
	}
	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_SEAL_IMAGES) {
		next.seal_images = pushed.seal_images;
	}
	if (pushed.present & DSERVER_SYSTEM_CONFIG_HAS_TRUST_STORE_PATH) {
		// `validate` made sure the string is terminated within the buffer
		strncpy(next.trust_store_path, pushed.trust_store_path, sizeof(next.trust_store_path) - 1);
	}

	std::unique_lock lock(_mutex);

	if (_config.generation > 0) {
		// as on macOS, where the SIP configuration can only be relaxed from recoveryOS,
		// a running prefix may only turn protections on: every flag in the new
		// configuration must already be in effect
		if ((next.csr_active_config & ~_config.csr_active_config) != 0) {
			return -EPERM;
		}
	}

	next.generation = _config.generation + 1;
	isFirst = (_config.generation == 0);
	_config = next;

	return 0;
};

dserver_system_config_t DarlingServer::SystemConfig::current() const {
	std::unique_lock lock(_mutex);
	return _config;
};
