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

#include <darlingserver/process.hpp>
#include <darlingserver/registry.hpp>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>
#include <darlingserver/logging.hpp>
#include <darlingserver/code-signing.hpp>
#include <darlingserver/system-config.hpp>
#include <darlingserver/iosurface.hpp>
#include <kern/cs_blobs.h>

#include <fstream>
#include <sstream>
#include <dirent.h>
#include <cstdio>
#include <cstring>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <atomic>
#include <algorithm>
#include <string>

#include "procmap-query.h"

static DarlingServer::Log processLog("process");

DarlingServer::Process::Process(ID id, NSID nsid, Architecture architecture, int pipe, bool forkChild):
	_pid(id),
	_nspid(nsid),
	_architecture(architecture)
{
	int pidfd = (pipe >= 0) ? pipe : syscall(SYS_pidfd_open, _pid, 0);
	if (pidfd < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to open pidfd for process");
	}

	_pidfd = std::make_shared<FD>(pidfd);

	// we could use stat instead of status, but it's more complicated with comm potentially getting in the way of parsing (it can include whitespace and parentheses)
	std::ifstream statusFile("/proc/" + std::to_string(id) + "/status");
	std::string line;

	std::shared_ptr<Process> parentProcess = nullptr;

	while (std::getline(statusFile, line)) {
		if (line.substr(0, sizeof("PPid") - 1) == "PPid") {
			auto pos = line.find_last_of('\t');
			std::string id;

			if (pos != line.npos) {
				id = line.substr(pos + 1);
			}

			if (id.empty()) {
				throw std::runtime_error("Failed to parse parent process ID");
			}

			if (auto maybeParentProcess = processRegistry().lookupEntryByID(std::stoi(id))) {
				parentProcess = *maybeParentProcess;
				_parentProcess = parentProcess;
			}

			break;
		}
	}

	if (parentProcess) {
		std::shared_lock parentLock(parentProcess->_rwlock);

		// inherit vchroot from parent process
		_vchrootDescriptor = parentProcess->_vchrootDescriptor;
		_cachedVchrootPath = parentProcess->_cachedVchrootPath;

		// inherit groups from parent process
		_groups = parentProcess->_groups;

		// a forked process runs the same code as its parent, in the same sandbox,
		// but has not denied attachment itself
		_csState = parentProcess->_csState;
		_csState.darling_flags = CodeSigning::darlingFlagsInheritedByFork(_csState.darling_flags);
		_csImage = parentProcess->_csImage;

		// fork does not change a task's architecture, only exec does. The task of a program run
		// under an emulator was registered by the host-native loader, so its fork child reports a
		// different architecture than its parent's task has.
		if (forkChild) {
			_architecture = parentProcess->_architecture;
		}
	} else {
		_resetCodeSigningState();

		// the first process has no parent to inherit from, so it may register once
		_csMayRegister = (_nspid == 1);
	}

	// NOTE: see thread.cpp for why it's okay to use `this` here
	_dtapeTask = dtape_task_create(parentProcess ? parentProcess->_dtapeTask : nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
	_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

	processLog.info() << "New process created with ID " << _pid << " and NSID " << _nspid;
};

DarlingServer::Process::Process(KernelProcessConstructorTag tag):
	_pid(-1),
	_nspid(0)
{
#if __x86_64__
	_architecture = Architecture::x86_64;
#elif __i386__
	_architecture = Architecture::i386;
#elif __aarch64__
	_architecture = Architecture::ARM64;
#elif __arm__
	_architecture = Architecture::ARM32;
#else
	#error Unknown architecture
#endif
	_resetCodeSigningState();
	_dtapeTask = dtape_task_create(nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
};

DarlingServer::Process::~Process() {
	processLog.info() << *this << ": process being destroyed" << processLog.endLog;
	_closeMapsDescriptor();
	_closeSmapsDescriptor();
};

DarlingServer::Process::ID DarlingServer::Process::id() const {
	return _pid;
};

DarlingServer::Process::NSID DarlingServer::Process::nsid() const {
	return _nspid;
};

DarlingServer::EternalID DarlingServer::Process::eternalID() const {
	return _eid;
};

void DarlingServer::Process::_setEternalID(EternalID eid) {
	_eid = eid;
};

std::vector<std::shared_ptr<DarlingServer::Thread>> DarlingServer::Process::threads() const {
	std::vector<std::shared_ptr<DarlingServer::Thread>> result;
	std::shared_lock lock(_rwlock);

	for (auto& [nsid, maybeThread]: _threads) {
		if (auto thread = maybeThread.lock()) {
			result.push_back(thread);
		}
	}

	return result;
};

std::string DarlingServer::Process::vchrootPath() const {
	std::shared_lock lock(_rwlock);
	return _cachedVchrootPath;
};

void DarlingServer::Process::setVchrootDirectory(std::shared_ptr<FD> directoryDescriptor) {
	std::unique_lock lock(_rwlock);
	_vchrootDescriptor = directoryDescriptor;

	char* tmp = new char[4096];

	auto fdPath = "/proc/self/fd/" + std::to_string(_vchrootDescriptor->fd());
	auto len = readlink(fdPath.c_str(), tmp, 4095);

	if (len < 0) {
		throw std::system_error(errno, std::generic_category(), "readlink");
	}

	tmp[len] = '\0';

	_cachedVchrootPath = std::string(tmp);
	delete[] tmp;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::currentProcess() {
	auto thread = Thread::currentThread();
	if (!thread) {
		return nullptr;
	}

	return thread->process();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::parentProcess() const {
	return _parentProcess.lock();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::kernelProcess() {
	static std::shared_ptr<Process> process = [&]() {
		auto proc = std::make_shared<Process>(KernelProcessConstructorTag());
		processRegistry().registerEntry(proc, true);
		return proc;
	}();
	return process;
};

bool DarlingServer::Process::startSuspended() const {
	std::shared_lock lock(_rwlock);
	return _startSuspended;
};

void DarlingServer::Process::setStartSuspended(bool startSuspended) {
	std::unique_lock lock(_rwlock);
	_startSuspended = startSuspended;
};

bool DarlingServer::Process::_readOrWriteMemory(bool isWrite, uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	struct iovec local;
	struct iovec remote;
	const auto func = isWrite ? process_vm_writev : process_vm_readv;
	static DarlingServer::Log processMemoryAccessLog("procmem");

	if (isDead()) {
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): process dead"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = ESRCH;
		}
		return false;
	}

	local.iov_base = localBuffer;
	local.iov_len = length;

	remote.iov_base = (void*)remoteAddress;
	remote.iov_len = length;

	if (func(id(), &local, 1, &remote, 1, 0) < 0) {
		int code = errno;
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): "
			<< code
			<< " ("
			<< strerror(code)
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = code;
		}
		return false;
	} else {
		processMemoryAccessLog.debug()
			<< "Successfully "
			<< (isWrite ? "wrote " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = 0;
		}
		return true;
	}
};

bool DarlingServer::Process::readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	return _readOrWriteMemory(false, remoteAddress, localBuffer, length, errorCode);
};

bool DarlingServer::Process::writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode) const {
	// the const_cast is safe; when writing to a process' memory, localBuffer is not modified
	return _readOrWriteMemory(true, remoteAddress, const_cast<void*>(localBuffer), length, errorCode);
};

void DarlingServer::Process::notifyCheckin(Architecture architecture, bool isFork) {
	std::unique_lock lock(_rwlock);

	bool didExec = _pendingReplacement;

	if (didExec) {
		// exec case

		processLog.info() << *this << ": replacing process with a new task (with architecture \"" << architectureToString(architecture) << "\")" << processLog.endLog;

		// clear all threads except the main thread
		std::shared_ptr<Thread> mainThread = nullptr;
		while (!_threads.empty()) {
			auto it = _threads.begin();
			auto thread = it->second.lock();
			lock.unlock();
			if (thread) {
				if (thread->_nstid == _nspid) {
					mainThread = thread;
				} else {
					thread->_process = nullptr;
					thread->notifyDead();
				}
			}
			lock.lock();
			_threads.erase(it);
		}
		if (!mainThread) {
			throw std::runtime_error("Main thread for process died?");
		}
		_threads[mainThread->nsid()] = mainThread;

		// update the process architecture
		_architecture = architecture;

		// the old `/proc/<pid>/maps` and smaps descriptors refer to the address space that the exec replaced
		_closeMapsDescriptor();
		_closeSmapsDescriptor();

		// replace the old task with a new task that inherits from it
		auto oldTask = _dtapeTask;
		auto newTask = dtape_task_create(oldTask, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
		_dtapeTask = newTask;

		// now replace the main thread's duct-taped thread with a new one
		auto oldThread = mainThread->_dtapeThread;
		auto newThread = dtape_thread_create(_dtapeTask, mainThread->_nstid, mainThread.get());
		mainThread->_dtapeThread = newThread;

		// the cancel flag's TSD slot belonged to the old image;
		// the new image registers its own when its libpthread initializes
		mainThread->_cancelMarkedAddress = 0;

		// the loader reports the new image's UUID once it has parsed the image
		_executableUuid = {};

		// destroy the main thread's old S2C semaphores
		dtape_semaphore_destroy(mainThread->_s2cPerformSempahore);
		mainThread->_s2cPerformSempahore = nullptr;
		dtape_semaphore_destroy(mainThread->_s2cReplySempahore);
		mainThread->_s2cReplySempahore = nullptr;
		dtape_semaphore_destroy(mainThread->_s2cInterruptEnterSemaphore);
		mainThread->_s2cInterruptEnterSemaphore = nullptr;
		dtape_semaphore_destroy(mainThread->_s2cInterruptExitSemaphore);
		mainThread->_s2cInterruptExitSemaphore = nullptr;

		// destroy the fork-wait semaphore
		dtape_semaphore_destroy(_dtapeForkWaitSemaphore);
		_dtapeForkWaitSemaphore = nullptr;

		// release the main thread's old duct-taped thread
		dtape_thread_release(oldThread);

		// release the old task
		dtape_task_release(oldTask);

		// create a new fork-wait semaphore for the new task
		_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

		// create new S2C semaphores for the main thread
		mainThread->_s2cPerformSempahore = dtape_semaphore_create(_dtapeTask, 1);
		mainThread->_s2cReplySempahore = dtape_semaphore_create(_dtapeTask, 0);
		mainThread->_s2cInterruptEnterSemaphore = dtape_semaphore_create(_dtapeTask, 0);
		mainThread->_s2cInterruptExitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

		// calls in flight or abandoned belonged to the old image; the new image starts with no S2C history
		{
			std::unique_lock threadLock(mainThread->_rwlock);
			mainThread->_s2cReply = std::nullopt;
			mainThread->_s2cCallInFlight = false;
			mainThread->_s2cStaleReplyPending = false;
			mainThread->_s2cStaleReplyUsedInterrupt = false;
			mainThread->_s2cInterruptAbandoned = 0;
			mainThread->_s2cInterruptEntered = false;
			mainThread->_s2cStaleMappingLength = 0;
			mainThread->_s2cStaleMappingReusable = false;
			mainThread->_s2cStaleMappings.clear();
			mainThread->_s2cReusableStaleMappings.clear();
		}

		// the new image has not been verified yet, and it starts under the policy in effect now;
		// a denial of attachment and a sandbox survive the exec
		{
			auto kept = CodeSigning::darlingFlagsKeptAcrossExec(_csState.darling_flags);
			_resetCodeSigningState();
			_csState.darling_flags |= kept;
			_csMayRegister = true;
		}
	}

	_pendingReplacement = false;

	lock.unlock();

	if (didExec) {
		// the image the process held IOSurfaces from is gone
		IOSurfaceRegistry::sharedInstance().forgetProcess(id());

		// notify listeners that we have exec'd (i.e. been replaced)
		_notifyListeningKqchannels(NOTE_EXEC, 0);
	} else if (isFork) {
		// only a fork child's check-in: its parent waits in fork() for exactly this one. a check-in
		// from an exec'd image whose exec has not been reported yet must not wake the parent, or the
		// parent's next fork() returns before that child has checked in and inherited its ports.
		// notify the parent process (if we have one) that we've arrived
		if (auto parent = _parentProcess.lock()) {
			// a forked child runs the parent's image
			setExecutablePath(parent->executablePath());
			setExecutableUuid(parent->executableUuid());

			{
				// the parent may have died (or be dying) before we checked in;
				// its fork-wait semaphore is gone then and there's no one left to wake up
				std::shared_lock parentLock(parent->_rwlock);
				if (parent->_dtapeForkWaitSemaphore) {
					dtape_semaphore_up(parent->_dtapeForkWaitSemaphore);
				}
			}
			parent->_notifyListeningKqchannels(NOTE_FORK, nsid());
		}
	}
};

void DarlingServer::Process::setPendingReplacement() {
	std::unique_lock lock(_rwlock);

	processLog.info() << "Process " << id() << " (" << nsid() << ") is now pending replacement" << processLog.endLog;

	_pendingReplacement = true;
};

void DarlingServer::Process::registerKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels[kqchan->_idForProcess()] = kqchan;
};

void DarlingServer::Process::unregisterKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels.erase(kqchan->_idForProcess());
};

bool DarlingServer::Process::waitForChildAfterFork() {
	// this function is always called within a microthread
	return dtape_semaphore_down_simple(_dtapeForkWaitSemaphore);
};

void DarlingServer::Process::registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan) {
	std::unique_lock lock(_rwlock);
	uintptr_t id = static_cast<std::shared_ptr<Kqchan>>(kqchan)->_idForProcess();
	_listeningKqchannels[id] = kqchan;
};

void DarlingServer::Process::unregisterListeningKqchan(uintptr_t kqchanID) {
	std::unique_lock lock(_rwlock);
	_listeningKqchannels.erase(kqchanID);
};

void DarlingServer::Process::_notifyListeningKqchannels(uint32_t event, int64_t data) {
	decltype(_listeningKqchannels) listeningKqchannels;

	// we do NOT want to be holding our rwlock when we notify the kqchannels; that can lead to deadlocks
	{
		std::shared_lock lock(_rwlock);
		listeningKqchannels = _listeningKqchannels;
	}

	for (auto& [id, maybeKqchan]: listeningKqchannels) {
		auto kqchan = maybeKqchan.lock();

		if (!kqchan) {
			continue;
		}

		kqchan->_notify(event, data);
	}
};

bool DarlingServer::Process::is64Bit() const {
	return _architecture == Architecture::x86_64 || _architecture == Architecture::ARM64;
};

DarlingServer::Process::Architecture DarlingServer::Process::architecture() const {
	return _architecture;
};

void DarlingServer::Process::logToStream(Log::Stream& stream) const {
	stream << "[P:" << _pid << "(" << _nspid << ")]";
};

// the fields of /proc/<pid>/stat and /proc/<pid>/task/<tid>/stat that we use
struct ProcStat {
	unsigned long long minorFaults;
	unsigned long long majorFaults;
	// in clock ticks
	unsigned long long userTime;
	unsigned long long systemTime;
};

static bool readProcStat(const std::string& path, ProcStat& stat) {
	std::ifstream file(path);
	std::string line;
	if (!std::getline(file, line)) {
		return false;
	}

	// the command name is parenthesized and may itself contain spaces and parentheses, so parse after the last ')';
	// the fields after it start with the state (field 3)
	auto endOfComm = line.rfind(')');
	if (endOfComm == std::string::npos) {
		return false;
	}

	std::istringstream fields(line.substr(endOfComm + 1));
	std::string field;
	stat = {};
	for (int index = 3; index <= 15; ++index) {
		if (!(fields >> field)) {
			return false;
		}
		unsigned long long value = std::strtoull(field.c_str(), nullptr, 10);
		if (index == 10) {
			stat.minorFaults = value;
		} else if (index == 12) {
			stat.majorFaults = value;
		} else if (index == 14) {
			stat.userTime = value;
		} else if (index == 15) {
			stat.systemTime = value;
		}
	}
	return true;
};

// calls `callback` with the ID of each thread of the host process; false if the threads can't be listed
template<class F>
static bool forEachHostThread(pid_t pid, F callback) {
	DIR* dir = opendir(("/proc/" + std::to_string(pid) + "/task").c_str());
	if (!dir) {
		return false;
	}
	while (auto entry = readdir(dir)) {
		char* end = nullptr;
		unsigned long tid = std::strtoul(entry->d_name, &end, 10);
		if (end != entry->d_name && *end == '\0') {
			callback(static_cast<pid_t>(tid));
		}
	}
	closedir(dir);
	return true;
};

// the host process whose /proc entries describe this task: the server itself for the kernel task
pid_t DarlingServer::Process::statisticsPID() const {
	return (_pid < 0) ? getpid() : _pid;
};

bool DarlingServer::Process::cpuTimes(CPUTimes& times) const {
	if (isDead()) {
		return false;
	}

	long ticksPerSecond = sysconf(_SC_CLK_TCK);
	if (ticksPerSecond <= 0) {
		ticksPerSecond = 100;
	}
	uint64_t nsPerTick = 1000000000ULL / ticksPerSecond;

	// the threads first, so that time they use in between does not count as that of exited threads
	// (the threads of the kernel task are not threads of Linux: all time of the server is that of the task)
	unsigned long long liveUser = 0;
	unsigned long long liveSystem = 0;
	if (_pid >= 0 && !forEachHostThread(statisticsPID(), [&](pid_t tid) {
		ProcStat stat;
		if (readProcStat("/proc/" + std::to_string(statisticsPID()) + "/task/" + std::to_string(tid) + "/stat", stat)) {
			liveUser += stat.userTime;
			liveSystem += stat.systemTime;
		}
	})) {
		return false;
	}

	// the process-wide counters also include the time of the threads that have exited
	ProcStat total;
	if (!readProcStat("/proc/" + std::to_string(statisticsPID()) + "/stat", total)) {
		return false;
	}

	times.liveUserNs = liveUser * nsPerTick;
	times.liveSystemNs = liveSystem * nsPerTick;
	times.terminatedUserNs = (total.userTime > liveUser) ? (total.userTime - liveUser) * nsPerTick : 0;
	times.terminatedSystemNs = (total.systemTime > liveSystem) ? (total.systemTime - liveSystem) * nsPerTick : 0;
	return true;
};

bool DarlingServer::Process::eventCounts(EventCounts& counts) const {
	if (isDead()) {
		return false;
	}

	ProcStat total;
	if (!readProcStat("/proc/" + std::to_string(statisticsPID()) + "/stat", total)) {
		return false;
	}

	counts.faults = total.minorFaults + total.majorFaults;
	// the faults that had to read from storage
	counts.pageins = total.majorFaults;
	counts.contextSwitches = 0;

	forEachHostThread(statisticsPID(), [&](pid_t tid) {
		std::ifstream status("/proc/" + std::to_string(statisticsPID()) + "/task/" + std::to_string(tid) + "/status");
		std::string line;
		while (std::getline(status, line)) {
			unsigned long long value = 0;
			if (sscanf(line.c_str(), "voluntary_ctxt_switches: %llu", &value) == 1 || sscanf(line.c_str(), "nonvoluntary_ctxt_switches: %llu", &value) == 1) {
				counts.contextSwitches += value;
			}
		}
	});

	return true;
};

DarlingServer::Process::MemoryInfo DarlingServer::Process::memoryInfo() const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryInfo");
	}

	MemoryInfo info {};
	std::ifstream file("/proc/" + std::to_string(statisticsPID()) + "/statm");

	if (!(file >> info.virtualSize >> info.residentSize)) {
		// the process died after the check above
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryInfo");
	}

	info.virtualSize *= sysconf(_SC_PAGESIZE);
	info.residentSize *= sysconf(_SC_PAGESIZE);

	// CHECKME: can different processes have different page sizes on Linux?
	info.pageSize = sysconf(_SC_PAGESIZE);

	// TODO
	info.regionCount = 0;

	// the breakdown: Linux has no counterpart of the compressor, so swap is the stand-in
	// for compressed memory in the footprint, and the rest follows Mach's definitions of
	// "internal" (anonymous) and "external" (file-backed) pages
	uint64_t rssAnon = 0, rssFile = 0, rssShmem = 0, vmSwap = 0, vmHwm = 0;
	bool haveBreakdown = false;
	{
		std::ifstream status("/proc/" + std::to_string(statisticsPID()) + "/status");
		std::string line;
		while (std::getline(status, line)) {
			unsigned long long kb = 0;
			char name[16] = {0};
			if (sscanf(line.c_str(), "%15[A-Za-z]: %llu kB", name, &kb) != 2) {
				continue;
			}
			if (strcmp(name, "RssAnon") == 0) {
				rssAnon = kb * 1024;
				haveBreakdown = true;
			} else if (strcmp(name, "RssFile") == 0) {
				rssFile = kb * 1024;
			} else if (strcmp(name, "RssShmem") == 0) {
				rssShmem = kb * 1024;
			} else if (strcmp(name, "VmSwap") == 0) {
				vmSwap = kb * 1024;
			} else if (strcmp(name, "VmHWM") == 0) {
				vmHwm = kb * 1024;
			}
		}
	}

	if (haveBreakdown) {
		info.internalSize = rssAnon + rssShmem;
		info.externalSize = rssFile;
		info.swappedSize = vmSwap;
	} else {
		// no per-type counters (kernels before 4.5): count everything resident as anonymous
		info.internalSize = info.residentSize;
	}
	info.physFootprint = info.internalSize + info.swappedSize;

	// The kernel's high-water mark can lag the resident size it has just reported by a
	// few pages (per-thread counter batching), so both peaks are also kept monotonic
	// here: a peak never goes down between queries.
	auto raisePeak = [](std::atomic<uint64_t>& peak, uint64_t value) {
		uint64_t current = peak.load(std::memory_order_relaxed);
		while (current < value && !peak.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
		}
		return std::max(current, value);
	};
	info.residentSizePeak = raisePeak(_residentSizePeak, std::max(vmHwm, info.residentSize));
	info.physFootprintPeak = raisePeak(_physFootprintPeak, info.physFootprint);

	return info;
};

// parses the "start-end perms offset" prefix of a `/proc/<pid>/maps` line
static bool parseMapsLine(const std::string& line, uintptr_t& start, uintptr_t& end, char (&perms)[8], uintptr_t& offset) {
	unsigned long long startValue = 0;
	unsigned long long endValue = 0;
	unsigned long long offsetValue = 0;
	char permsValue[8] = {0};

	if (sscanf(line.c_str(), "%llx-%llx %7s %llx", &startValue, &endValue, permsValue, &offsetValue) != 4) {
		return false;
	}

	start = startValue;
	end = endValue;
	offset = offsetValue;
	memcpy(perms, permsValue, sizeof(perms));
	return true;
};

// runs PROCMAP_QUERY on a `/proc/<pid>/maps` descriptor; returns 0 or an errno value
static int procmapQuery(int mapsFd, uint64_t address, uint64_t flags, struct procmap_query& query) {
	memset(&query, 0, sizeof(query));
	query.size = sizeof(query);
	query.query_flags = flags;
	query.query_addr = address;
	return (ioctl(mapsFd, PROCMAP_QUERY, &query) == 0) ? 0 : errno;
};

static int procmapProtection(uint64_t vmaFlags) {
	int protection = 0;
	if (vmaFlags & PROCMAP_QUERY_VMA_READABLE) {
		protection |= PROT_READ;
	}
	if (vmaFlags & PROCMAP_QUERY_VMA_WRITABLE) {
		protection |= PROT_WRITE;
	}
	if (vmaFlags & PROCMAP_QUERY_VMA_EXECUTABLE) {
		protection |= PROT_EXEC;
	}
	return protection;
};

// set once the running kernel turns out not to support PROCMAP_QUERY
static std::atomic<bool> procmapQueryUnsupported(false);

void DarlingServer::Process::_closeMapsDescriptor() {
	std::unique_lock lock(_mapsMutex);
	if (_mapsFd >= 0) {
		close(_mapsFd);
		_mapsFd = -1;
	}
};

//
// Looks up the VMA that covers `address` (or, with `coveringOrNext`, the first one above it) with PROCMAP_QUERY.
//
// Returns false if the lookup found nothing or could not be done at all; the caller then parses the text of
// `/proc/<pid>/maps`, which also lists the gate area ("[vsyscall]") that PROCMAP_QUERY does not report.
//
bool DarlingServer::Process::_queryRegion(uintptr_t address, bool coveringOrNext, uintptr_t& start, uintptr_t& end, int& protection, bool& shared, uint64_t& offset, uint64_t* device, uint64_t* inode) const {
	if (procmapQueryUnsupported.load(std::memory_order_relaxed)) {
		return false;
	}

	std::unique_lock lock(_mapsMutex);

	// a cached descriptor can go stale (e.g. its address space is gone after an exec); retry once with a fresh one
	for (int attempt = 0; attempt < 2; ++attempt) {
		bool fresh = false;

		if (_mapsFd < 0) {
			_mapsFd = open(("/proc/" + std::to_string(_pid) + "/maps").c_str(), O_RDONLY | O_CLOEXEC);
			if (_mapsFd < 0) {
				return false;
			}
			fresh = true;
		}

		struct procmap_query query;
		int error = procmapQuery(_mapsFd, address, coveringOrNext ? PROCMAP_QUERY_COVERING_OR_NEXT_VMA : 0, query);

		if (error == 0) {
			start = query.vma_start;
			end = query.vma_end;
			protection = procmapProtection(query.vma_flags);
			shared = (query.vma_flags & PROCMAP_QUERY_VMA_SHARED) != 0;
			offset = query.vma_offset;
			if (device) {
				*device = ((uint64_t)query.dev_major << 32) | query.dev_minor;
			}
			if (inode) {
				*inode = query.inode;
			}
			return true;
		}

		if (error == ENOENT) {
			return false;
		}

		close(_mapsFd);
		_mapsFd = -1;

		// ENOTTY: the kernel predates PROCMAP_QUERY; EINVAL on a fresh descriptor: it rejects this layout of the query
		if (error == ENOTTY || (fresh && error == EINVAL)) {
			procmapQueryUnsupported.store(true, std::memory_order_relaxed);
			return false;
		}

		if (fresh) {
			return false;
		}
	}

	return false;
};

void DarlingServer::Process::_closeSmapsDescriptor() {
	std::unique_lock lock(_smapsMutex);
	if (_smaps.fd >= 0) {
		close(_smaps.fd);
	}
	_smaps = SmapsCursor();
};

//
// Reads `/proc/<pid>/smaps` forward from the cursor until the counts of the mapping that starts at `startAddress` are
// parsed. `found` tells whether that mapping was reached; the return value is false only if the file could not be read.
//
// The reads are small and the parsing stops at the last count that is needed, so the kernel, which writes the text of
// one mapping at a time as the file is read, does not produce the text of mappings that were not asked for yet (their
// counts would be out of date by the time they are asked for).
//
bool DarlingServer::Process::_scanSmaps(uintptr_t startAddress, uint64_t& privateKiB, uint64_t& sharedKiB, bool& found) const {
	found = false;

	for (;;) {
		if (_smaps.haveRegion) {
			if (_smaps.regionStart > startAddress) {
				// the mapping is not there any more (or was never)
				return true;
			}
			if (_smaps.regionStart == startAddress && _smaps.regionComplete) {
				privateKiB = _smaps.privateKiB;
				sharedKiB = _smaps.sharedKiB;
				_smaps.regionServed = true;
				found = true;
				return true;
			}
		}

		auto lineEnd = _smaps.pending.find('\n');
		if (lineEnd == std::string::npos) {
			char chunk[128];
			ssize_t count;
			do {
				count = read(_smaps.fd, chunk, sizeof(chunk));
			} while (count < 0 && errno == EINTR);
			if (count <= 0) {
				// the end of the file (or an error, e.g. the address space is gone): there is no such mapping after the cursor
				return count == 0;
			}
			_smaps.pending.append(chunk, count);
			continue;
		}

		std::string line = _smaps.pending.substr(0, lineEnd);
		_smaps.pending.erase(0, lineEnd + 1);

		// a mapping's header line starts with a (lowercase hexadecimal) address; the field lines, with a capitalized name
		if (!line.empty() && ((line[0] >= '0' && line[0] <= '9') || (line[0] >= 'a' && line[0] <= 'f'))) {
			uintptr_t start;
			uintptr_t end;
			char perms[8];
			uintptr_t offset;
			if (parseMapsLine(line, start, end, perms, offset)) {
				_smaps.haveRegion = true;
				_smaps.regionStart = start;
				_smaps.privateKiB = 0;
				_smaps.sharedKiB = 0;
				_smaps.regionComplete = false;
				_smaps.regionServed = false;
			}
			continue;
		}

		if (!_smaps.haveRegion || _smaps.regionStart != startAddress) {
			continue;
		}

		char field[32];
		unsigned long long kib;
		if (sscanf(line.c_str(), "%31[^:]: %llu kB", field, &kib) != 2) {
			continue;
		}
		if (strcmp(field, "Private_Clean") == 0 || strcmp(field, "Private_Dirty") == 0) {
			_smaps.privateKiB += kib;
			if (field[8] == 'D') {
				// the last of the counts (Shared_* come before Private_*)
				_smaps.regionComplete = true;
			}
		} else if (strcmp(field, "Shared_Clean") == 0 || strcmp(field, "Shared_Dirty") == 0) {
			_smaps.sharedKiB += kib;
		}
	}
};

bool DarlingServer::Process::regionResidency(uintptr_t startAddress, uint64_t& privatePages, uint64_t& sharedPages) const {
	if (isDead()) {
		return false;
	}

	uint64_t privateKiB = 0;
	uint64_t sharedKiB = 0;
	bool found = false;

	{
		std::unique_lock lock(_smapsMutex);

		// Reading on from where the previous call stopped serves a walk over the mappings in ascending order.
		// Anything else (an earlier mapping, the same mapping again, a mapping that was not found) starts reading the
		// file from its start, which also gives the counts as they are now.
		bool resumable = _smaps.fd >= 0 && _smaps.haveRegion && (startAddress > _smaps.regionStart || (startAddress == _smaps.regionStart && !_smaps.regionServed));

		auto restart = [&]() {
			if (_smaps.fd >= 0) {
				close(_smaps.fd);
			}
			_smaps = SmapsCursor();
			_smaps.fd = open(("/proc/" + std::to_string(_pid) + "/smaps").c_str(), O_RDONLY | O_CLOEXEC);
			return _smaps.fd >= 0;
		};

		if (!resumable && !restart()) {
			return false;
		}

		bool readable = _scanSmaps(startAddress, privateKiB, sharedKiB, found);

		if (!found && resumable) {
			if (!restart()) {
				return false;
			}
			readable = _scanSmaps(startAddress, privateKiB, sharedKiB, found);
		}

		if (!readable) {
			// the end of the file, or it can't be read: nothing more to resume
			close(_smaps.fd);
			_smaps = SmapsCursor();
		}
	}

	if (!found) {
		return false;
	}

	const uint64_t pageKiB = sysconf(_SC_PAGESIZE) / 1024;
	privatePages = privateKiB / pageKiB;
	sharedPages = sharedKiB / pageKiB;
	return true;
};

DarlingServer::Process::MemoryRegionInfo DarlingServer::Process::memoryRegionInfo(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryRegionInfo");
	}

	MemoryRegionInfo info = {};
	uintptr_t endAddress;

	if (_queryRegion(address, false, info.startAddress, endAddress, info.protection, info.shared, info.mapOffset, &info.device, &info.inode)) {
		info.pageCount = (endAddress - info.startAddress) / sysconf(_SC_PAGESIZE);
		return info;
	}

	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	while (std::getline(file, line)) {
		char perms[8];
		uintptr_t mapOffset;

		if (!parseMapsLine(line, info.startAddress, endAddress, perms, mapOffset)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		if (endAddress <= address || info.startAddress > address) {
			continue;
		}

		info.pageCount = (endAddress - info.startAddress) / sysconf(_SC_PAGESIZE);

		info.mapOffset = mapOffset;

		info.protection = 0;

		if (strchr(perms, 'r')) {
			info.protection |= PROT_READ;
		}
		if (strchr(perms, 'w')) {
			info.protection |= PROT_WRITE;
		}
		if (strchr(perms, 'x')) {
			info.protection |= PROT_EXEC;
		}

		info.shared = strchr(perms, 's') != nullptr;

		// the "major:minor inode" fields that follow the offset
		unsigned int deviceMajor = 0;
		unsigned int deviceMinor = 0;
		unsigned long long inode = 0;
		if (sscanf(line.c_str(), "%*x-%*x %*s %*x %x:%x %llu", &deviceMajor, &deviceMinor, &inode) == 3) {
			info.device = ((uint64_t)deviceMajor << 32) | deviceMinor;
			info.inode = inode;
		}

		return info;
	}

	processLog.warning() << *this << ": Address 0x" << std::hex << address << " not found in \"/proc/" << std::dec << _pid << "/maps\"" << processLog.endLog;
	throw std::system_error(EFAULT, std::generic_category());
};

#if DSERVER_EXTENDED_DEBUG

void DarlingServer::Process::_registerName(uint32_t name, uintptr_t pointer) {
	std::unique_lock lock(_rwlock);
	_registeredNames[name] = pointer;
};

void DarlingServer::Process::_unregisterName(uint32_t name) {
	std::unique_lock lock(_rwlock);
	_registeredNames.erase(name);
};

void DarlingServer::Process::_addPortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	auto& members = _portSetMembers[portSetID];
	members.insert(portID);
};

void DarlingServer::Process::_removePortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	if (_portSetMembers.find(portSetID) != _portSetMembers.end()) {
		auto& members = _portSetMembers[portSetID];
		members.erase(portID);
		if (members.empty()) {
			_portSetMembers.erase(portSetID);
		}
	}
};

void DarlingServer::Process::_clearPortSet(dtape_port_set_id_t portSetID) {
	std::unique_lock lock(_rwlock);
	_portSetMembers.erase(portSetID);
};

#endif

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::tracerProcess() const {
	std::shared_lock lock(_rwlock);
	return _tracerProcess.lock();
};

bool DarlingServer::Process::setTracerProcess(std::shared_ptr<Process> tracerProcess) {
	std::unique_lock lock(_rwlock);
	if (!_tracerProcess.expired()) {
		return false;
	}
	_tracerProcess = tracerProcess;
	return true;
};

bool DarlingServer::Process::clearTracerProcess(std::shared_ptr<Process> tracerProcess) {
	std::unique_lock lock(_rwlock);
	auto current = _tracerProcess.lock();
	if (current && current != tracerProcess) {
		return false;
	}
	_tracerProcess.reset();
	return true;
};

void DarlingServer::Process::_resetCodeSigningState() {
	static std::atomic<uint64_t> nextGeneration{1};
	auto config = SystemConfig::sharedInstance().current();

	memset(&_csState, 0, sizeof(_csState));
	_csState.version = DSERVER_CS_STATE_VERSION;
	_csState.size = sizeof(_csState);
	_csState.status = dserver_cs_status_unregistered;
	_csState.code_signing_policy = config.code_signing_policy;
	_csState.csr_active_config = config.csr_active_config;
	_csState.generation = nextGeneration++;
	_csImage = nullptr;
	_csMayRegister = false;
};

uint32_t DarlingServer::Process::guestUID() const {
	int uid = -1;
	std::shared_lock lock(_rwlock);
	dtape_task_uidgid(_dtapeTask, -1, -1, &uid, nullptr);
	return static_cast<uint32_t>(uid);
};

dserver_cs_state_t DarlingServer::Process::codeSigningState() const {
	std::shared_lock lock(_rwlock);
	return _csState;
};

std::shared_ptr<const DarlingServer::CodeSigning::Image> DarlingServer::Process::codeSigningImage() const {
	std::shared_lock lock(_rwlock);
	return _csImage;
};

bool DarlingServer::Process::registerCodeSigningImage(std::shared_ptr<const CodeSigning::Image> image) {
	std::unique_lock lock(_rwlock);

	// registering once per exec only matters when a code signing policy is in effect
	if (!image || (!_csMayRegister && _csState.code_signing_policy == dserver_code_signing_policy_enforce)) {
		return false;
	}
	_csMayRegister = false;

	auto policy = _csState.code_signing_policy;
	auto csr = _csState.csr_active_config;
	auto generation = _csState.generation;
	auto kept = CodeSigning::darlingFlagsKeptAcrossExec(_csState.darling_flags);

	_csState = image->state;
	_csState.code_signing_policy = policy;
	_csState.csr_active_config = csr;
	_csState.generation = generation;
	_csState.darling_flags = (image->state.darling_flags & DSERVER_CS_TRUST_STORE) | kept;
	_csImage = (image->state.status == dserver_cs_status_valid) ? image : nullptr;

	return true;
};

uint32_t DarlingServer::Process::updateCodeSigningFlags(uint32_t set, uint32_t clear) {
	std::unique_lock lock(_rwlock);

	// only a validly signed process has flags to change; clearing CS_VALID is permanent
	if (_csState.status == dserver_cs_status_valid) {
		_csState.flags = (_csState.flags | set) & ~clear;
	}

	return _csState.flags;
};

void DarlingServer::Process::denyAttach() {
	std::unique_lock lock(_rwlock);
	_csState.darling_flags |= DSERVER_CS_DENY_ATTACH;
};

void DarlingServer::Process::markSandboxed() {
	std::unique_lock lock(_rwlock);
	_csState.darling_flags |= DSERVER_CS_SANDBOXED;
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Process::_pickS2CThread(void) const {
	if (isDead()) {
		return nullptr;
	}

	// if we're the process for the current thread (i.e. we're the current process), use the current thread
	if (currentProcess().get() == this) {
		return Thread::currentThread();
	}

	// otherwise, pick any thread to perform the call

	std::shared_ptr<Thread> thread = nullptr;

	{
		std::shared_lock lock(_rwlock);
		for (auto& [id, weakThread]: _threads) {
			thread = weakThread.lock();
			if (thread) {
				break;
			}
		}
	}

	return thread;
};

std::string DarlingServer::Process::executablePath() const {
	std::shared_lock lock(_rwlock);
	return _executablePath;
};

void DarlingServer::Process::setExecutablePath(std::string path) {
	std::unique_lock lock(_rwlock);
	_executablePath = std::move(path);
};

std::array<uint8_t, 16> DarlingServer::Process::executableUuid() const {
	std::shared_lock lock(_rwlock);
	return _executableUuid;
};

void DarlingServer::Process::setExecutableUuid(const std::array<uint8_t, 16>& uuid) {
	std::unique_lock lock(_rwlock);
	_executableUuid = uuid;
};

uintptr_t DarlingServer::Process::allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite) {
	auto thread = _pickS2CThread();

	if (!thread) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	return thread->allocatePages(pageCount, protection, addressHint, fixed, overwrite);
};

void DarlingServer::Process::freePages(uintptr_t address, size_t pageCount) {
	auto thread = _pickS2CThread();

	if (!thread) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	return thread->freePages(address, pageCount);
};

uintptr_t DarlingServer::Process::mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite) {
	auto thread = _pickS2CThread();

	if (!thread) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	return thread->mapFile(fd, pageCount, protection, addressHint, pageOffset, fixed, overwrite);
};

void DarlingServer::Process::changeProtection(uintptr_t address, size_t pageCount, int protection) {
	auto thread = _pickS2CThread();

	if (!thread) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	return thread->changeProtection(address, pageCount, protection);
};

void DarlingServer::Process::syncMemory(uintptr_t address, size_t size, int sync_flags) {
	auto thread = _pickS2CThread();

	if (!thread) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	return thread->syncMemory(address, size, sync_flags);
};

uintptr_t DarlingServer::Process::getNextRegion(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call getNextRegion");
	}

	if (address != UINTPTR_MAX) {
		uintptr_t start;
		uintptr_t end;
		int protection;
		bool shared;
		uint64_t offset;

		// the VMA covering or following `address + 1`; if that one starts at or below `address`, the next region follows it
		bool found = _queryRegion(address + 1, true, start, end, protection, shared, offset);
		if (found && start <= address) {
			found = _queryRegion(end, true, start, end, protection, shared, offset);
		}
		if (found) {
			return start;
		}
	}

	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	while (std::getline(file, line)) {
		uintptr_t startAddress;
		uintptr_t endAddress;
		uintptr_t mapOffset;
		char perms[8];

		if (!parseMapsLine(line, startAddress, endAddress, perms, mapOffset)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		if (startAddress <= address) {
			continue;
		}

		// /proc/<pid>/maps is sorted in ascending order, so as soon as we find a line with a starting address greater than `address`, that's the next region

		return startAddress;
	}

	return 0;
};

void DarlingServer::Process::notifyDead() {
	decltype(_threads) threads;
	{
		std::unique_lock lock(_rwlock);
		if (_dead) {
			return;
		}

		processLog.info() << *this << ": process dying" << processLog.endLog;
		_dead = true;
		threads = _threads;

		// clear out all kqchannels we own
		_kqchannels.clear();
	}

	// keep ourselves alive until the duct-taped context is done
	_selfReference = shared_from_this();

	// a dead process holds no IOSurfaces
	IOSurfaceRegistry::sharedInstance().forgetProcess(id());

	// TODO: get exit status
	_notifyListeningKqchannels(NOTE_EXIT, 0);

	dtape_task_dying(_dtapeTask);

	// notify all our threads that we're dead
	for (auto [id, maybeThread]: threads) {
		auto thread = maybeThread.lock();
		if (!thread) {
			continue;
		}
		thread->notifyDead();
	}

	// schedule the duct-taped task to be released
	// dtape_thread_release needs a microthread context, so we call it within a kernel microthread
	// also destroy the fork-wait semaphore here
	Thread::kernelAsync([self = shared_from_this()]() {
		dtape_semaphore_t* forkWaitSemaphore = nullptr;
		{
			std::unique_lock lock(self->_rwlock);
			forkWaitSemaphore = self->_dtapeForkWaitSemaphore;
			self->_dtapeForkWaitSemaphore = nullptr;
		}
		if (forkWaitSemaphore) {
			dtape_semaphore_destroy(forkWaitSemaphore);
		}
		dtape_task_release(self->_dtapeTask);
		self->_dtapeTask = nullptr;
	});

	processRegistry().unregisterEntry(shared_from_this());
};

void DarlingServer::Process::_dispose() {
	_selfReference = nullptr;
};

bool DarlingServer::Process::isDead() const {
	std::shared_lock lock(_rwlock);
	return _dead;
};

std::vector<uint32_t> DarlingServer::Process::groups() const {
	std::shared_lock lock(_rwlock);
	return _groups;
};

void DarlingServer::Process::setGroups(const std::vector<uint32_t>& groups) {
	std::unique_lock lock(_rwlock);
	_groups = groups;
};
