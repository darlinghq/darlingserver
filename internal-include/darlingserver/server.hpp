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

#ifndef _DARLINGSERVER_SERVER_HPP_
#define _DARLINGSERVER_SERVER_HPP_

#include <string>
#include <sys/epoll.h>
#include <thread>

#include <darlingserver/message.hpp>
#include <darlingserver/workers.hpp>
#include <darlingserver/call.hpp>
#include <darlingserver/registry.hpp>
#include <darlingserver/utility.hpp>
#include <darlingserver/monitor.hpp>

namespace DarlingServer {
	// NOTE: server instances MUST be created with `new` rather than as a normal local/stack variable
	class Server {
		friend class Monitor;

	private:
		int _listenerSocket;
		std::string _prefix;
		std::string _socketPath;
		int _epollFD;
		MessageQueue _inbox;
		MessageQueue _outbox;
		WorkQueue<std::shared_ptr<Thread>> _workQueue;
		bool _canRead = false;
		bool _canWrite = true;
		int _wakeupFD;
		int _timerFD;
		std::mutex _timerLock;
		std::vector<std::shared_ptr<Monitor>> _monitors;
		std::vector<std::shared_ptr<Monitor>> _monitorsWaitingToDie;
		std::mutex _monitorsLock;

		void _worker(std::shared_ptr<Thread> thread);

		friend struct ::DTapeHooks;

	public:
		Server(std::string prefix);
		~Server();

		Server(const Server&) = delete;
		Server& operator=(const Server&) = delete;
		Server(Server&&) = delete;
		Server& operator=(Server&&) = delete;

		void start();

		void monitorProcess(std::shared_ptr<Process> process);

		std::string prefix() const;

		static Server& sharedInstance();

		void scheduleThread(std::shared_ptr<Thread> thread);

		void addMonitor(std::shared_ptr<Monitor> monitor);
		void removeMonitor(std::shared_ptr<Monitor> monitor);

		void sendMessage(Message&& message);
	};
};

#endif // _DARLINGSERVER_SERVER_HPP_
