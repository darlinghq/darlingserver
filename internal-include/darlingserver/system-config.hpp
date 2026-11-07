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

#ifndef _DARLINGSERVER_SYSTEM_CONFIG_HPP_
#define _DARLINGSERVER_SYSTEM_CONFIG_HPP_

#include <darlingserver/rpc-supplement.h>

#include <mutex>

namespace DarlingServer {
	/**
	 * The configuration pushed by the guest configuration daemon (see `dserver_system_config_t`).
	 *
	 * This class only validates and stores the values; checking who may push is up to the caller.
	 */
	class SystemConfig {
	private:
		mutable std::mutex _mutex;
		dserver_system_config_t _config;

	public:
		/**
		 * Starts out with the built-in defaults (generation 0).
		 */
		SystemConfig();

		SystemConfig(const SystemConfig&) = delete;
		SystemConfig& operator=(const SystemConfig&) = delete;

		static SystemConfig& sharedInstance();

		/**
		 * Checks a pushed configuration without applying it.
		 *
		 * @returns 0 if it is well-formed, or `-EINVAL`.
		 */
		static int validate(const dserver_system_config_t& pushed);

		/**
		 * Validates @p pushed and, if it is acceptable, makes it the configuration in effect.
		 * Nothing is changed when the push is rejected.
		 *
		 * @param isFirst Set to `true` when this was the first accepted push.
		 * @returns 0, `-EINVAL` for a malformed push, or `-EPERM` when the push would relax
		 *          `csr_active_config` after the first push.
		 */
		int apply(const dserver_system_config_t& pushed, bool& isFirst);

		/**
		 * A copy of the configuration in effect, with `generation` filled in.
		 */
		dserver_system_config_t current() const;
	};
};

#endif // _DARLINGSERVER_SYSTEM_CONFIG_HPP_
