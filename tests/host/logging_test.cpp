// Log levels in src/logging.cpp (compiled unchanged against tests/host/logging-stubs): Log::enabled
// reports the DSERVER_LOG_LEVEL cutoff, and a stream for a dropped level does not format anything,
// so a Loggable written to it is never asked to describe itself and nothing reaches the log file.
#include <darlingserver/logging.hpp>
#include <darlingserver/server.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static std::string prefixDir;

Server& Server::sharedInstance() {
	static Server server;
	return server;
}

std::string Server::prefix() const {
	return prefixDir;
}

struct CountingLoggable: public Loggable {
	mutable int calls = 0;
	const char* text;
	CountingLoggable(const char* text): text(text) {}
	void logToStream(Log::Stream& stream) const override {
		++calls;
		stream << text;
	}
};

struct CountingValue {
	mutable int calls = 0;
};

static std::ostream& operator<<(std::ostream& os, const CountingValue& value) {
	++value.calls;
	return os << "counted-value";
}

static std::string logContents() {
	std::ifstream in(prefixDir + "/private/var/log/dserver.log");
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

int main(int, char** argv) {
	prefixDir = argv[1];
	setenv("DSERVER_LOG_LEVEL", "info", 1);

	Log log("test");

	CHECK(!log.enabled(Log::Type::Debug), "debug messages are disabled at level info");
	CHECK(log.enabled(Log::Type::Info), "info messages are enabled at level info");
	CHECK(log.enabled(Log::Type::Warning), "warning messages are enabled at level info");
	CHECK(log.enabled(Log::Type::Error), "error messages are enabled at level info");

	CountingLoggable dropped("dropped-loggable");
	CountingValue droppedValue;
	log.debug() << "dropped-text " << droppedValue << dropped << log.endLog;
	CHECK(dropped.calls == 0, "a Loggable written to a disabled level is not formatted");
	CHECK(droppedValue.calls == 0, "a value written to a disabled level is not formatted");

	CountingLoggable kept("kept-loggable");
	CountingValue keptValue;
	log.info() << "kept-text " << keptValue << " " << kept << log.endLog;
	CHECK(kept.calls == 1, "a Loggable written to an enabled level is formatted once");
	CHECK(keptValue.calls == 1, "a value written to an enabled level is formatted once");

	auto contents = logContents();
	CHECK(contents.find("kept-text counted-value kept-loggable") != std::string::npos, "the enabled message reaches the log file");
	CHECK(contents.find("dropped") == std::string::npos, "the disabled message does not reach the log file");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
