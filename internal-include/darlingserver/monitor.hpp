#ifndef _DARLINGSERVER_MONITOR_HPP_
#define _DARLINGSERVER_MONITOR_HPP_

#include <sys/epoll.h>
#include <memory>
#include <functional>
#include <mutex>

#include <darlingserver/utility.hpp>

namespace DarlingServer {
	class Server;

	class Monitor {
		friend class Server;

	public:
		enum class Event: uint32_t {
			Readable = EPOLLIN,
			Writable = EPOLLOUT,
			Error = EPOLLERR,
			HangUp = EPOLLHUP,
			ReadHangUp = EPOLLRDHUP,
		};

	private:
		std::shared_ptr<FD> _fd;
		std::function<void(std::shared_ptr<Monitor>, Event)> _callback;
		Server* _server;
		Event _userEvents;
		uint32_t _events;
		std::mutex _lock;

	public:
		Monitor(std::shared_ptr<FD> descriptor, Event events, bool edgeTriggered, bool oneshot, std::function<void(std::shared_ptr<Monitor>, Event)> callback);

		void enable(bool edgeTriggered = false, bool oneshot = false);
		void disable();
	};
};

inline DarlingServer::Monitor::Event operator|(DarlingServer::Monitor::Event a, DarlingServer::Monitor::Event b) {
	using UnderlyingType = std::underlying_type_t<DarlingServer::Monitor::Event>;
	return static_cast<DarlingServer::Monitor::Event>(static_cast<UnderlyingType>(a) | static_cast<UnderlyingType>(b));
};

inline DarlingServer::Monitor::Event operator&(DarlingServer::Monitor::Event a, DarlingServer::Monitor::Event b) {
	using UnderlyingType = std::underlying_type_t<DarlingServer::Monitor::Event>;
	return static_cast<DarlingServer::Monitor::Event>(static_cast<UnderlyingType>(a) & static_cast<UnderlyingType>(b));
};

#endif // _DARLINGSERVER_MONITOR_HPP_
