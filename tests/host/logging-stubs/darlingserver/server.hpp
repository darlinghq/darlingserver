// Stand-in for the server header, for compiling src/logging.cpp on its own (logging_test.cpp).
#pragma once
#include <string>

namespace DarlingServer {
	class Server {
	public:
		static Server& sharedInstance();
		std::string prefix() const;
	};
};
