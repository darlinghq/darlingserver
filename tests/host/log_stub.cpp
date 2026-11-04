// Stand-in for src/logging.cpp (which pulls in the whole server); prints each finished line to stderr.
#include <darlingserver/logging.hpp>
#include <cstdio>

const DarlingServer::Log::EndLog DarlingServer::Log::endLog{};

DarlingServer::Log::Log(std::string category): _category(category) {}
DarlingServer::Log::Stream DarlingServer::Log::debug() const { return Stream(Type::Debug, *this); }
DarlingServer::Log::Stream DarlingServer::Log::info() const { return Stream(Type::Info, *this); }
DarlingServer::Log::Stream DarlingServer::Log::warning() const { return Stream(Type::Warning, *this); }
DarlingServer::Log::Stream DarlingServer::Log::error() const { return Stream(Type::Error, *this); }

DarlingServer::Log::Stream::Stream(Type type, const Log& log): _type(type), _log(log) {}
DarlingServer::Log::Stream::~Stream() {}
DarlingServer::Log::Stream& DarlingServer::Log::Stream::operator<<(EndLog) {
	std::fprintf(stderr, "  log[%s]: %s\n", _log._category.c_str(), _buffer.str().c_str());
	_buffer.str("");
	return *this;
}
