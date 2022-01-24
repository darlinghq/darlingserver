#include <darlingserver/utility.hpp>
#include <unistd.h>

DarlingServer::FD::FD():
	_fd(-1)
	{};

DarlingServer::FD::FD(int fd):
	_fd(fd)
	{};

DarlingServer::FD::~FD() {
	if (_fd != -1) {
		close(_fd);
	}
};

DarlingServer::FD::FD(FD&& other):
	_fd(other._fd)
{
	other._fd = -1;
};

DarlingServer::FD& DarlingServer::FD::operator=(FD&& other) {
	if (_fd != -1) {
		close(_fd);
	}
	_fd = other._fd;
	other._fd = -1;
	return *this;
};

int DarlingServer::FD::fd() const {
	return _fd;
};
