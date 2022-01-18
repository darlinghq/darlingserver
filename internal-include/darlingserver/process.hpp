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

#ifndef _DARLINGSERVER_PROCESS_HPP_
#define _DARLINGSERVER_PROCESS_HPP_

#include <sys/types.h>
#include <memory>
#include <vector>
#include <mutex>
#include <shared_mutex>

#include <darlingserver/duct-tape.h>

struct DTapeHooks;

namespace DarlingServer {
	class Thread;
	class Server;

	class Process {
		friend class Thread;
		friend class Server;

	private:
		pid_t _pid;
		pid_t _nspid;
		int _pidfd;
		mutable std::shared_mutex _rwlock;
		std::vector<std::weak_ptr<Thread>> _threads;
		std::string _vchrootPath;
		dtape_task_handle_t _dtapeTask;

		std::weak_ptr<Process> _parentProcess;

		void _unregisterThreads();

		struct KernelProcessConstructorTag {};

		friend struct ::DTapeHooks;

	public:
		using ID = pid_t;
		using NSID = ID;

		Process(ID id, NSID nsid);
		Process(KernelProcessConstructorTag tag);
		~Process();

		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;
		Process(Process&&) = delete;
		Process& operator=(Process&&) = delete;

		/**
		 * The PID of this Process as seen from darlingserver's namespace.
		 */
		ID id() const;

		/**
		 * The PID of this Process as seen from within the container (i.e. launchd's namespace).
		 */
		NSID nsid() const;

		std::vector<std::shared_ptr<Thread>> threads() const;

		std::string vchrootPath() const;
		void setVchrootPath(std::string path);

		std::shared_ptr<Process> parentProcess() const;

		static std::shared_ptr<Process> currentProcess();
		static std::shared_ptr<Process> kernelProcess();
	};
};

#endif // _DARLINGSERVER_PROCESS_HPP_
