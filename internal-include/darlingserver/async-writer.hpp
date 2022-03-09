#ifndef _DARLINGSERVER_ASYNC_WRITER_HPP_
#define _DARLINGSERVER_ASYNC_WRITER_HPP_

#include <darlingserver/monitor.hpp>
#include <sstream>

namespace DarlingServer {
	/**
	 * A class to write data to a file descriptor asynchronously.
	 *
	 * This allows you to push data as you please and the class
	 * will take care of sending the data in a non-blocking manner.
	 *
	 * Additionally, the class will ensure that all the data gets written.
	 * Once you give the writer some data, it will keep itself alive
	 * until that data is fully written.
	 *
	 * @note This class requires the FD to be non-blocking.
	 *       It will automatically make it non-blocking.
	 *       Note that this can have adverse effects, e.g. with pipes.
	 */
	class AsyncWriter: public std::enable_shared_from_this<AsyncWriter> {
	private:
		std::mutex _mutex;
		std::weak_ptr<Monitor> _monitor;
		std::shared_ptr<FD> _fd;
		std::vector<uint8_t> _buffer;
		bool _canSend = true;
		std::shared_ptr<AsyncWriter> _keepMeAliveUntilEmpty = nullptr;

		void init(std::shared_ptr<FD> fd);

		void _trySendLocked();

	public:
		~AsyncWriter();

		class Stream;

		Stream stream();

		void write(const char* data, size_t length);
		void write(const std::string& data);

		static std::shared_ptr<AsyncWriter> make(std::shared_ptr<FD> fd);
	};

	class AsyncWriter::Stream {
		friend class AsyncWriter;

	private:
		std::shared_ptr<AsyncWriter> _writer;
		std::stringstream _stream;

		Stream(std::shared_ptr<AsyncWriter> writer);

	public:
		~Stream();

		template<class T>
		Stream& operator<<(const T& value) {
			_stream << value;
			return *this;
		};
	};
};

#endif // _DARLINGSERVER_ASYNC_WRITER_HPP_
