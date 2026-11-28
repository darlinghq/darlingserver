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

#include <array>
#include <atomic>
#include <sys/types.h>
#include <memory>
#include <vector>
#include <mutex>
#include <string>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

#include <darlingserver/duct-tape.h>
#include <darlingserver/utility.hpp>
#include <darlingserver/kqchan.hpp>
#include <darlingserver/rpc.h>
#include <darlingserver/logging.hpp>
#include <darlingserver/registry.hpp>
#include <darlingserver/rpc-supplement.h>

struct DTapeHooks;

namespace DarlingServer {
	class Thread;

	namespace CodeSigning {
		struct Image;
	};
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

			// highest resident size the process has reached (VmHWM, kept monotonic)
			uint64_t residentSizePeak;

			// Linux's closest analogues of the Mach task_vm_info breakdown, from the
			// Rss*/VmSwap lines of /proc/<pid>/status (see Process::memoryInfo())
			uint64_t internalSize; // anonymous and shmem pages (RssAnon + RssShmem)
			uint64_t externalSize; // file-backed pages (RssFile)
			uint64_t swappedSize; // pages that are only in swap (VmSwap)

			// internalSize + swappedSize: what the process costs the system
			uint64_t physFootprint;

			// highest physFootprint seen by any query of this process (sampled)
			uint64_t physFootprintPeak;
		};

		struct MemoryRegionInfo {
			uintptr_t startAddress;
			uint64_t pageCount;
			int protection;
			uint64_t mapOffset;
			uint64_t device;
			uint64_t inode;
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

		// highest values returned by memoryInfo() so far, so that the peaks never decrease
		mutable std::atomic<uint64_t> _residentSizePeak{0};
		mutable std::atomic<uint64_t> _physFootprintPeak{0};

		// `/proc/<pid>/maps`, kept open for PROCMAP_QUERY region lookups; guarded by its own mutex
		// so a lookup never issues the ioctl on a descriptor that another thread closed.
		mutable std::mutex _mapsMutex;
		mutable int _mapsFd = -1;
		bool _queryRegion(uintptr_t address, bool coveringOrNext, uintptr_t& start, uintptr_t& end, int& protection, bool& shared, uint64_t& offset, uint64_t* device = nullptr, uint64_t* inode = nullptr) const;
		void _closeMapsDescriptor();

		// `/proc/<pid>/smaps`, read front to back by regionResidency(). The kernel produces the text of one mapping
		// at a time, as the descriptor is read, so keeping the descriptor and its parse state between calls lets an
		// ascending walk over the mappings read the file once (instead of from its start for every mapping).
		struct SmapsCursor {
			int fd = -1;
			// text read from the descriptor that has not been parsed yet
			std::string pending;
			// the mapping whose header was parsed last
			bool haveRegion = false;
			uintptr_t regionStart = 0;
			uint64_t privateKiB = 0;
			uint64_t sharedKiB = 0;
			// all the counts of the mapping have been parsed
			bool regionComplete = false;
			// the mapping's counts were returned to a caller (a later query for it must read the file afresh)
			bool regionServed = false;
		};
		mutable std::mutex _smapsMutex;
		mutable SmapsCursor _smaps;
		bool _scanSmaps(uintptr_t startAddress, uint64_t& privateKiB, uint64_t& sharedKiB, bool& found) const;
		void _closeSmapsDescriptor();
		std::weak_ptr<Process> _parentProcess;
		// a fork child whose forking process was gone when it checked in; no one waits for it in fork()
		bool _forkParentGone = false;
		bool _startSuspended = false;
		bool _stoppedAtStart = false;
		// execs announced at checkout and not yet completed by the new image's main-thread check-in
		// or by a failure report (see noteExecCheckout)
		unsigned int _execsInFlight = 0;
		std::unordered_map<uintptr_t, std::shared_ptr<Kqchan>> _kqchannels;
		std::unordered_map<uintptr_t, std::weak_ptr<Kqchan::Process>> _listeningKqchannels;
		dtape_semaphore_t* _dtapeForkWaitSemaphore;
		Architecture _architecture;
		std::weak_ptr<Process> _tracerProcess;
		std::string _executablePath;
		std::array<uint8_t, 16> _executableUuid = {};
		bool _dead = false;
		std::shared_ptr<Process> _selfReference = nullptr;
		std::vector<uint32_t> _groups;

		// code signing state; see `dserver_cs_state_t`
		dserver_cs_state_t _csState;
		std::shared_ptr<const CodeSigning::Image> _csImage;
		bool _csMayRegister = false;
		void _resetCodeSigningState();

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

		void _dispose(dtape_task_t* task);

		void _setEternalID(EternalID eid);

	public:
		using ID = pid_t;
		using NSID = ID;

		/**
		 * `forkParentNSID` is, for a fork child, the container PID of the process that called fork(), as the child saw it
		 * before the fork. The child may check in after that process has died, when the kernel has already made the
		 * child the reaper's, so the parent recorded here is the one the child names rather than the one the kernel
		 * reports. Zero means the caller does not know it.
		 */
		Process(ID id, NSID nsid, Architecture architecture, int pipe = -1, bool forkChild = false, NSID forkParentNSID = 0);
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
		bool stoppedAtStart() const;
		void setStoppedAtStart(bool stoppedAtStart);

		bool readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode = nullptr) const;
		bool writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode = nullptr) const;

		/**
		 * Handles a check-in from this process's image. `isFork` is set by a new child after fork();
		 * only that check-in ends its parent's wait in fork(). `fromMainThread`: the checking-in thread is the process's
		 * main thread; only such a check-in can be the one an exec'd image makes.
		 */
		void notifyCheckin(Architecture architecture, bool isFork, bool fromMainThread);
		// an execve of a Darling image is about to happen (its checkout, before the reply that lets it go ahead)
		void noteExecCheckout();
		// an execve announced by noteExecCheckout() failed (its exec pipe got the failure byte)
		void noteExecFailed();

		void registerKqchan(std::shared_ptr<Kqchan> kqchan);
		void unregisterKqchan(std::shared_ptr<Kqchan> kqchan);

		void registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan);
		void unregisterListeningKqchan(uintptr_t kqchanID);

		/**
		 * Waits until a forked child has checked in.
		 * Returns `false` if the wait was interrupted (e.g. by a signal) before that.
		 */
		bool waitForChildAfterFork();

		bool is64Bit() const;
		Architecture architecture() const;

		// CPU time of the threads of the process, in nanoseconds (Linux counts it in clock ticks)
		struct CPUTimes {
			// threads that have exited
			uint64_t terminatedUserNs;
			uint64_t terminatedSystemNs;
			// threads that are still running
			uint64_t liveUserNs;
			uint64_t liveSystemNs;
		};

		// counters of events Linux keeps for the process
		struct EventCounts {
			uint64_t faults;
			uint64_t pageins;
			// of the threads that still exist
			uint64_t contextSwitches;
		};

		// the host process whose statistics describe this task (the server itself for the kernel task)
		pid_t statisticsPID() const;

		// false if the process is gone
		bool cpuTimes(CPUTimes& times) const;
		bool eventCounts(EventCounts& counts) const;

		MemoryInfo memoryInfo() const;
		MemoryRegionInfo memoryRegionInfo(uintptr_t address) const;
		// counts the resident pages of the mapping that starts at `startAddress`, split into pages only this process
		// maps and pages shared with other mappings (from `/proc/<pid>/smaps`); false if there is no such mapping
		bool regionResidency(uintptr_t startAddress, uint64_t& privatePages, uint64_t& sharedPages) const;

		std::shared_ptr<Process> tracerProcess() const;
		bool setTracerProcess(std::shared_ptr<Process> tracerProcess);
		/**
		 * Forgets the tracer, but only if it is `tracerProcess`. Returns whether the process has no tracer afterwards.
		 */
		bool clearTracerProcess(std::shared_ptr<Process> tracerProcess);

		/**
		 * The process's (guest) user ID, as the process itself set it.
		 */
		uint32_t guestUID() const;

		/**
		 * The process's code signing state.
		 */
		dserver_cs_state_t codeSigningState() const;

		/**
		 * The image the process registered, if a signed one was.
		 */
		std::shared_ptr<const CodeSigning::Image> codeSigningImage() const;

		/**
		 * Records the image the process starts from.
		 *
		 * @returns `false` if, under the `enforce` policy, the process may not register an image (a
		 *          forked process, or one that already registered since it started).
		 */
		bool registerCodeSigningImage(std::shared_ptr<const CodeSigning::Image> image);

		/**
		 * Sets and clears `CS_*` flags; the caller decides which ones may be changed.
		 *
		 * @returns The new flags.
		 */
		uint32_t updateCodeSigningFlags(uint32_t set, uint32_t clear);

		/**
		 * Records that the process called ptrace(PT_DENY_ATTACH).
		 */
		void denyAttach();

		/**
		 * Records that the process applied a sandbox profile. This cannot be undone; the
		 * process's forked children and the images it execs stay marked.
		 */
		void markSandboxed();

		std::string executablePath() const;
		void setExecutablePath(std::string path);

		/**
		 * The LC_UUID of the main executable (all zeros when it has none).
		 */
		std::array<uint8_t, 16> executableUuid() const;
		void setExecutableUuid(const std::array<uint8_t, 16>& uuid);

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
