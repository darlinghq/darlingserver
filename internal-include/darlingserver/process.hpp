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
#include <unordered_set>

#include <darlingserver/duct-tape.h>
#include <darlingserver/utility.hpp>
#include <darlingserver/kqchan.hpp>
#include <darlingserver/rpc.h>
#include <darlingserver/logging.hpp>
#include <darlingserver/registry.hpp>

struct DTapeHooks;

namespace DarlingServer {
	class Thread;
	class Server;
	class Call;

	class Process: public Loggable, public std::enable_shared_from_this<Process> {
		friend class Thread;
		friend class Server;
		friend class Call; // HACK; see Call.cpp
		friend class Kqchan;
		friend class Registry<Process>;

	public:
		enum class Architecture {
			Invalid = dserver_rpc_architecture_invalid,
			i386 = dserver_rpc_architecture_i386,
			x86_64 = dserver_rpc_architecture_x86_64,
			ARM32 = dserver_rpc_architecture_arm32,
			ARM64 = dserver_rpc_architecture_arm64,
		};

		static constexpr const char* architectureToString(Architecture architecture) {
			switch (architecture) {
				case Architecture::i386:    return "i386";
				case Architecture::x86_64:  return "x86_64";
				case Architecture::ARM32:   return "ARM32";
				case Architecture::ARM64:   return "ARM64";
				default: return "Unknown";
			}
		}

		struct MemoryInfo {
			uint64_t virtualSize;
			uint64_t residentSize;
			uint64_t pageSize;
			uint64_t regionCount;
		};

		struct MemoryRegionInfo {
			uintptr_t startAddress;
			uint64_t pageCount;
			int protection;
			uint64_t mapOffset;
			bool shared;
		};

	private:
		pid_t _pid;
		pid_t _nspid;
		EternalID _eid;
		std::shared_ptr<FD> _pidfd;
		mutable std::shared_mutex _rwlock;
		std::unordered_map<uint64_t, std::weak_ptr<Thread>> _threads;
		std::string _cachedVchrootPath;
		std::shared_ptr<FD> _vchrootDescriptor;
		dtape_task_t* _dtapeTask;
		std::weak_ptr<Process> _parentProcess;
		bool _startSuspended = false;
		bool _pendingReplacement = false;
		std::unordered_map<uintptr_t, std::shared_ptr<Kqchan>> _kqchannels;
		std::unordered_map<uintptr_t, std::weak_ptr<Kqchan::Process>> _listeningKqchannels;
		dtape_semaphore_t* _dtapeForkWaitSemaphore;
		Architecture _architecture;
		std::weak_ptr<Process> _tracerProcess;
		std::string _executablePath;
		bool _dead = false;
		std::shared_ptr<Process> _selfReference = nullptr;
		std::vector<uint32_t> _groups;

#if DSERVER_EXTENDED_DEBUG
		std::unordered_map<uint32_t, uintptr_t> _registeredNames;
		std::unordered_map<dtape_port_set_id_t, std::unordered_set<dtape_port_id_t>> _portSetMembers;
#endif

		struct KernelProcessConstructorTag {};

		friend struct ::DTapeHooks;

		bool _readOrWriteMemory(bool isWrite, uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const;

		void _notifyListeningKqchannels(uint32_t event, int64_t data);

#if DSERVER_EXTENDED_DEBUG
		void _registerName(uint32_t name, uintptr_t pointer);
		void _unregisterName(uint32_t name);
		void _addPortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID);
		void _removePortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID);
		void _clearPortSet(dtape_port_set_id_t portSetID);
#endif

		std::shared_ptr<Thread> _pickS2CThread(void) const;

		void _dispose();

		void _setEternalID(EternalID eid);

	public:
		using ID = pid_t;
		using NSID = ID;

		Process(ID id, NSID nsid, Architecture architecture, int pipe = -1);
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

		EternalID eternalID() const;

		std::vector<std::shared_ptr<Thread>> threads() const;

		std::string vchrootPath() const;
		void setVchrootDirectory(std::shared_ptr<FD> directoryDescriptor);

		std::shared_ptr<Process> parentProcess() const;

		bool startSuspended() const;
		void setStartSuspended(bool startSuspended);

		bool readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode = nullptr) const;
		bool writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode = nullptr) const;

		void notifyCheckin(Architecture architecture);
		void setPendingReplacement();

		void registerKqchan(std::shared_ptr<Kqchan> kqchan);
		void unregisterKqchan(std::shared_ptr<Kqchan> kqchan);

		void registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan);
		void unregisterListeningKqchan(uintptr_t kqchanID);

		void waitForChildAfterFork();

		bool is64Bit() const;
		Architecture architecture() const;

		MemoryInfo memoryInfo() const;
		MemoryRegionInfo memoryRegionInfo(uintptr_t address) const;

		std::shared_ptr<Process> tracerProcess() const;
		bool setTracerProcess(std::shared_ptr<Process> tracerProcess);

		std::string executablePath() const;
		void setExecutablePath(std::string path);

		uintptr_t allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite);
		void freePages(uintptr_t address, size_t pageCount);
		uintptr_t mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite);
		void changeProtection(uintptr_t address, size_t pageCount, int protection);
		void syncMemory(uintptr_t address, size_t size, int sync_flags);

		uintptr_t getNextRegion(uintptr_t address) const;

		/**
		 * Informs this Process instance that the process it was managing has died.
		 */
		void notifyDead();
		bool isDead() const;

		static std::shared_ptr<Process> currentProcess();
		static std::shared_ptr<Process> kernelProcess();

		void logToStream(Log::Stream& stream) const;

		std::vector<uint32_t> groups() const;
		void setGroups(const std::vector<uint32_t>& groups);
	};
};

#endif // _DARLINGSERVER_PROCESS_HPP_
