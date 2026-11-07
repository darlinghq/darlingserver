// Stand-in for the process header, for compiling src/logging.cpp on its own (logging_test.cpp).
#pragma once
#include <memory>
#include <sys/types.h>

namespace DarlingServer {
	class Process {
	public:
		static std::shared_ptr<Process> currentProcess() { return nullptr; }
		pid_t id() const { return 0; }
		pid_t nsid() const { return 0; }
	};
};
