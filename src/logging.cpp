/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
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

#include <darlingserver/logging.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/thread.hpp>
#include <darlingserver/process.hpp>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>

DarlingServer::Log::Log(std::string category):
	_category(category)
	{};

DarlingServer::Log::Stream::Stream(Type type, const Log& log):
	_type(type),
	_log(log)
	{};

DarlingServer::Log::Stream::~Stream() {
	*this << endLog;
};

DarlingServer::Log::Stream& DarlingServer::Log::Stream::operator<<(EndLog value) {
	auto str = _buffer.str();
	if (!str.empty()) {
		_log._log(_type, str);
		_buffer.str(std::string());
		_buffer.clear();
	}
	return *this;
};

DarlingServer::Log::Stream& DarlingServer::Log::Stream::operator<<(const Loggable& loggable) {
	loggable.logToStream(*this);
	return *this;
};

DarlingServer::Log::Stream DarlingServer::Log::debug() const {
	return Stream(Type::Debug, *this);
};

DarlingServer::Log::Stream DarlingServer::Log::info() const {
	return Stream(Type::Info, *this);
};

DarlingServer::Log::Stream DarlingServer::Log::warning() const {
	return Stream(Type::Warning, *this);
};

DarlingServer::Log::Stream DarlingServer::Log::error() const {
	return Stream(Type::Error, *this);
};

std::string DarlingServer::Log::_typeToString(Type type) {
	switch (type) {
		case Type::Debug:
			return "Debug";
		case Type::Info:
			return "Info";
		case Type::Warning:
			return "Warning";
		case Type::Error:
			return "Error";
		default:
			return "Unknown";
	}
};

void DarlingServer::Log::_log(Type type, std::string message) const {
	// NOTE: we use POSIX file APIs because we want to append each message to the log file atomically,
	//       and as far as i can tell, C++ fstreams provide no such guarantee (that they won't write in chunks).
	static int logFile = []() {
		std::filesystem::path path(Server::sharedInstance().prefix() + "/private/var/log/dserver.log");
		std::filesystem::create_directories(path.parent_path());
		return open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT);
	}();

	static bool logToStderr = []() {
		auto val = getenv("DSERVER_LOG_STDERR");
		return val && strlen(val) >= 1 && (val[0] == 't' || val[0] == 'T' || val[0] == '1');
	}();

	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	double secs = (double)time.tv_sec + ((double)time.tv_nsec / 1.0e9);
	auto currentProcess = Process::currentProcess();
	auto currentThread = Thread::currentThread();
	std::string pid = currentProcess ? (std::string("[P:") + std::to_string(currentProcess->id()) + "(" + std::to_string(currentProcess->nsid()) + ")]") : "";
	std::string tid = currentThread ? (std::string("[T:") + std::to_string(currentThread->id()) + "(" + std::to_string(currentThread->nsid()) + ")]") : "";
	std::string messageToLog = "[" + std::to_string(secs) + "](" + _category + ", " + _typeToString(type) + ")" + pid + tid + " " + message + "\n";

	write(logFile, messageToLog.c_str(), messageToLog.size());

	if (logToStderr) {
		write(STDERR_FILENO, messageToLog.c_str(), messageToLog.size());
	}
};
