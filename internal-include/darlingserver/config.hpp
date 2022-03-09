#ifndef _DARLINGSERVER_CONFIG_HPP_
#define _DARLINGSERVER_CONFIG_HPP_

#include <darling-config.h>
#include <string>

namespace DarlingServer {
	namespace Config {
		// NOTE: you should not rely on these values being `constexpr`;
		//       in the future, there may be a way to change them during startup.

		constexpr std::string_view defaultMldrPath = LIBEXEC_PATH "/usr/libexec/darling/mldr";

		// this would actually probably be better as a workqueue construction parameter
		constexpr bool singleThreadedWorkQueue = DSERVER_SINGLE_THREADED;
	};
};

#endif // _DARLINGSERVER_CONFIG_HPP_
