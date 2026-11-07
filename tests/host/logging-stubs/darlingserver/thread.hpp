// Stand-in for the thread header, for compiling src/logging.cpp on its own (logging_test.cpp).
#pragma once
#include <memory>
#include <sys/types.h>

namespace DarlingServer {
	class Thread {
	public:
		static std::shared_ptr<Thread> currentThread() { return nullptr; }
		pid_t id() const { return 0; }
		pid_t nsid() const { return 0; }
	};
};
