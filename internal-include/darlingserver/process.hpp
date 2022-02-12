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
#include <unordered_map>

#include <darlingserver/duct-tape.h>
#include <darlingserver/utility.hpp>
#include <darlingserver/kqchan.hpp>

struct DTapeHooks;

namespace DarlingServer {
	class Thread;
	class Server;
	class Call;

	class Process {
		friend class Thread;
		friend class Server;
		friend class Call; // HACK; see Call.cpp
		friend class Kqchan;

	private:
		pid_t _pid;
		pid_t _nspid;
		std::shared_ptr<FD> _pidfd;
		mutable std::shared_mutex _rwlock;
		std::vector<std::weak_ptr<Thread>> _threads;
		std::string _cachedVchrootPath;
		std::shared_ptr<FD> _vchrootDescriptor;
		dtape_task_t* _dtapeTask;
		std::weak_ptr<Process> _parentProcess;
		bool _startSuspended = false;
		bool _pendingReplacement = false;
		std::unordered_map<uintptr_t, std::shared_ptr<Kqchan>> _kqchannels;
		std::unordered_map<uintptr_t, std::weak_ptr<Kqchan::Process>> _listeningKqchannels;
		dtape_semaphore_t* _dtapeForkWaitSemaphore;

		void _unregisterThreads();

		struct KernelProcessConstructorTag {};

		friend struct ::DTapeHooks;

		bool _readOrWriteMemory(bool isWrite, uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const;

		void _notifyListeningKqchannels(uint32_t event, int64_t data);

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
		void setVchrootDirectory(std::shared_ptr<FD> directoryDescriptor);

		std::shared_ptr<Process> parentProcess() const;

		bool startSuspended() const;
		void setStartSuspended(bool startSuspended);

		bool readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode = nullptr) const;
		bool writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode = nullptr) const;

		void notifyCheckin();
		void setPendingReplacement();

		void registerKqchan(std::shared_ptr<Kqchan> kqchan);
		void unregisterKqchan(std::shared_ptr<Kqchan> kqchan);

		void registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan);
		void unregisterListeningKqchan(uintptr_t kqchanID);

		void waitForChildAfterFork();

		static std::shared_ptr<Process> currentProcess();
		static std::shared_ptr<Process> kernelProcess();
	};
};

#endif // _DARLINGSERVER_PROCESS_HPP_
