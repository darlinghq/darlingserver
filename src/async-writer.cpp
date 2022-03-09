#include <darlingserver/async-writer.hpp>
#include <darlingserver/server.hpp>

#include <sys/fcntl.h>

//
// writer
//

DarlingServer::AsyncWriter::~AsyncWriter() {
	if (auto monitor = _monitor.lock()) {
		Server::sharedInstance().removeMonitor(monitor);
	}
};

void DarlingServer::AsyncWriter::init(std::shared_ptr<FD> fd) {
	_fd = fd;

	int flags = fcntl(_fd->fd(), F_GETFL);
	if (flags < 0) {
		throw std::system_error(errno, std::generic_category());
	}

	if (fcntl(_fd->fd(), F_SETFL, flags | O_NONBLOCK) < 0) {
		throw std::system_error(errno, std::generic_category());
	}

	auto weakSelf = weak_from_this();
	auto monitor = std::make_shared<Monitor>(_fd, Monitor::Event::Writable | Monitor::Event::HangUp, true, false, [weakSelf](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
		auto self = weakSelf.lock();
		if (!self) {
			return;
		}

		if (!!(events & Monitor::Event::HangUp)) {
			Server::sharedInstance().removeMonitor(monitor);
			self->_monitor.reset();
			return;
		}

		if (!!(events & Monitor::Event::Writable)) {
			std::unique_lock lock(self->_mutex);
			self->_canSend = true;
			self->_trySendLocked();
		}
	});
	_monitor = monitor;

	Server::sharedInstance().addMonitor(monitor);
};

void DarlingServer::AsyncWriter::_trySendLocked() {
	do {
		auto written = ::write(_fd->fd(), _buffer.data(), _buffer.size());
		if (written < 0) {
			if (errno == EINTR) {
				// just try again
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// we can't write anymore for now
				_canSend = false;
			} else {
				throw std::system_error(errno, std::generic_category());
			}
		} else {
			_buffer.erase(_buffer.begin(), _buffer.begin() + written);

			if (_buffer.empty()) {
				// we've written all the data we had;
				// we can now die if no one else is holding a reference to us
				_keepMeAliveUntilEmpty = nullptr;
				break;
			}
		}
	} while (_canSend);
};

std::shared_ptr<DarlingServer::AsyncWriter> DarlingServer::AsyncWriter::make(std::shared_ptr<FD> fd) {
	auto writer = std::make_shared<AsyncWriter>();
	writer->init(fd);
	return writer;
};

DarlingServer::AsyncWriter::Stream DarlingServer::AsyncWriter::stream() {
	return AsyncWriter::Stream(shared_from_this());
};

void DarlingServer::AsyncWriter::write(const char* data, size_t length) {
	if (length == 0) {
		return;
	}

	std::unique_lock lock(_mutex);
	_buffer.insert(_buffer.end(), data, data + length);

	// okay, the buffer is now non-empty;
	// let's ensure we stay alive at least until we finish writing all the data
	_keepMeAliveUntilEmpty = shared_from_this();

	_trySendLocked();
};

void DarlingServer::AsyncWriter::write(const std::string& data) {
	return write(data.data(), data.length());
};

//
// stream
//

DarlingServer::AsyncWriter::Stream::Stream(std::shared_ptr<AsyncWriter> writer):
	_writer(writer)
	{};

DarlingServer::AsyncWriter::Stream::~Stream() {
	_writer->write(_stream.str());
};
