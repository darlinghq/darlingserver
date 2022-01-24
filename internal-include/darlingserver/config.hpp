#ifndef _DARLINGSERVER_CONFIG_HPP_
#define _DARLINGSERVER_CONFIG_HPP_

#include <darling-config.h>
#include <string>

namespace DarlingServer {
	namespace Config {
		constexpr std::string_view defaultMldrPath = LIBEXEC_PATH "/usr/libexec/darling/mldr";
	};
};

#endif // _DARLINGSERVER_CONFIG_HPP_
