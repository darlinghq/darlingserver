#ifndef _DARLINGSERVER_CONFIG_HPP_
#define _DARLINGSERVER_CONFIG_HPP_

#include <darling-config.h>
#include <string>
#include <utility>

namespace DarlingServer {
	namespace Config {
		// NOTE: you should not rely on these values being `constexpr`;
		//       they may be changed during startup.

		// The directory holding the read-only system image. It is LIBEXEC_PATH unless main() sets another one
		// before any thread is started (see RunMode::resolveLibexecPath for when that is allowed).
		inline std::string& libexecPathStorage() {
			static std::string path = LIBEXEC_PATH;
			return path;
		};

		inline const std::string& libexecPath() {
			return libexecPathStorage();
		};

		inline void setLibexecPath(std::string path) {
			libexecPathStorage() = std::move(path);
		};

		inline std::string defaultMldrPath() {
			return libexecPath() + "/usr/libexec/darling/mldr";
		};

		// this would actually probably be better as a workqueue construction parameter
		constexpr bool singleThreadedWorkQueue = DSERVER_SINGLE_THREADED;
	};
};

#endif // _DARLINGSERVER_CONFIG_HPP_
