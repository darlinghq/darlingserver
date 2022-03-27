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

#include <fstream>
#include <regex>

#include <sys/mman.h>

static DarlingServer::Log processLog("process");

DarlingServer::Process::Process(ID id, NSID nsid, Architecture architecture):
	_pid(id),
	_nspid(nsid),
	_architecture(architecture)
{
	int pidfd = syscall(SYS_pidfd_open, _pid, 0);
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
	_dtapeTask = dtape_task_create(nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
};

DarlingServer::Process::~Process() {
	processLog.info() << "Process with ID " << _pid << " and NSID " << _nspid << " being destroyed" << processLog.endLog;

	_unregisterThreads();

	// TODO: get exit status
	_notifyListeningKqchannels(NOTE_EXIT, 0);

	dtape_task_dying(_dtapeTask);

	// schedule the duct-taped task to be destroyed
	// dtape_thread_destroy needs a microthread context, so we call it within a kernel microthread
	// also destroy the fork-wait semaphore here
	Thread::kernelAsync([dtapeTask = _dtapeTask, dtapeForkWaitSemaphore = _dtapeForkWaitSemaphore]() {
		if (dtapeForkWaitSemaphore) {
			dtape_semaphore_destroy(dtapeForkWaitSemaphore);
		}
		dtape_task_destroy(dtapeTask);
	});
};

void DarlingServer::Process::_unregisterThreads() {
	std::unique_lock lock(_rwlock);
	while (!_threads.empty()) {
		auto it = _threads.begin();
		auto thread = it->second.lock();
		lock.unlock();
		if (thread) {
			thread->_process = std::weak_ptr<Process>();
			threadRegistry().unregisterEntry(thread);
		}
		lock.lock();
		_threads.erase(it);
	}
};

DarlingServer::Process::ID DarlingServer::Process::id() const {
	return _pid;
};

DarlingServer::Process::NSID DarlingServer::Process::nsid() const {
	return _nspid;
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
			<< " byte(s) at "
			<< remoteAddress
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
			<< " byte(s) at "
			<< remoteAddress
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

void DarlingServer::Process::notifyCheckin(Architecture architecture) {
	std::unique_lock lock(_rwlock);

	if (_pendingReplacement) {
		// exec case

		processLog.info() << "Replacing process " << id() << " (" << nsid() << ") with a new task" << processLog.endLog;

		// also, clear all threads except the main thread
		// (see _unregisterThreads)
		std::shared_ptr<Thread> mainThread = nullptr;
		while (!_threads.empty()) {
			auto it = _threads.begin();
			auto thread = it->second.lock();
			lock.unlock();
			if (thread) {
				if (thread->_nstid == _nspid) {
					mainThread = thread;
				} else {
					thread->_process = std::weak_ptr<Process>();
					threadRegistry().unregisterEntry(thread);
				}
			}
			lock.lock();
			_threads.erase(it);
		}
		if (!mainThread) {
			throw std::runtime_error("Main thread for process died?");
		}
		_threads[mainThread->nsid()] = mainThread;

		// replace the old task with a new task that inherits from it
		auto oldTask = _dtapeTask;
		auto newTask = dtape_task_create(oldTask, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
		_dtapeTask = newTask;

		// now replace the main thread's duct-taped thread with a new one
		auto oldThread = mainThread->_dtapeThread;
		auto newThread = dtape_thread_create(_dtapeTask, mainThread->_nstid, mainThread.get());
		mainThread->_dtapeThread = newThread;

		// destroy the main thread's old S2C semaphores
		dtape_semaphore_destroy(mainThread->_s2cPerformSempahore);
		mainThread->_s2cPerformSempahore = nullptr;
		dtape_semaphore_destroy(mainThread->_s2cReplySempahore);
		mainThread->_s2cReplySempahore = nullptr;

		// destroy the fork-wait semaphore
		dtape_semaphore_destroy(_dtapeForkWaitSemaphore);
		_dtapeForkWaitSemaphore = nullptr;

		// destroy the main thread's old duct-taped thread
		dtape_thread_destroy(oldThread);

		// destroy the old task
		dtape_task_destroy(oldTask);

		// create a new fork-wait semaphore for the new task
		_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

		// create new S2C semaphores for the main thread
		mainThread->_s2cPerformSempahore = dtape_semaphore_create(_dtapeTask, 1);
		mainThread->_s2cReplySempahore = dtape_semaphore_create(_dtapeTask, 0);

		// notify listeners that we have exec'd (i.e. been replaced)
		_notifyListeningKqchannelsLocked(NOTE_EXEC, 0);
	} else {
		// fork case

		if (architecture != _architecture) {
			throw std::runtime_error("Impossible: parent process architecture != child process architecture on fork");
		}

		// notify the parent process (if we have one) that we've arrived
		if (auto parent = _parentProcess.lock()) {
			dtape_semaphore_up(parent->_dtapeForkWaitSemaphore);
			parent->_notifyListeningKqchannels(NOTE_FORK, nsid());
		}
	}

	_pendingReplacement = false;
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

void DarlingServer::Process::waitForChildAfterFork() {
	// this function is always called within a microthread
	dtape_semaphore_down_simple(_dtapeForkWaitSemaphore);
};

void DarlingServer::Process::_registerListeningKqchanLocked(std::shared_ptr<Kqchan::Process> kqchan) {
	uintptr_t id = static_cast<std::shared_ptr<Kqchan>>(kqchan)->_idForProcess();
	_listeningKqchannels[id] = kqchan;
};

void DarlingServer::Process::registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan) {
	std::unique_lock lock(_rwlock);
	_registerListeningKqchanLocked(kqchan);
};

void DarlingServer::Process::unregisterListeningKqchan(uintptr_t kqchanID) {
	std::unique_lock lock(_rwlock);
	_listeningKqchannels.erase(kqchanID);
};

/**
 * @pre Must hold #_rwlock at least for reading.
 */
void DarlingServer::Process::_notifyListeningKqchannelsLocked(uint32_t event, int64_t data) {
	for (auto& [id, maybeKqchan]: _listeningKqchannels) {
		auto kqchan = maybeKqchan.lock();

		if (!kqchan) {
			continue;
		}

		kqchan->_notify(event, data);
	}
};

void DarlingServer::Process::_notifyListeningKqchannels(uint32_t event, int64_t data) {
	std::shared_lock lock(_rwlock);
	_notifyListeningKqchannelsLocked(event, data);
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

DarlingServer::Process::MemoryInfo DarlingServer::Process::memoryInfo() const {
	MemoryInfo info;
	std::ifstream file("/proc/" + std::to_string(_pid) + "/statm");

	file >> info.virtualSize >> info.residentSize;

	info.virtualSize *= sysconf(_SC_PAGESIZE);
	info.residentSize *= sysconf(_SC_PAGESIZE);

	// CHECKME: can different processes have different page sizes on Linux?
	info.pageSize = sysconf(_SC_PAGESIZE);

	// TODO
	info.regionCount = 0;

	return info;
};

static const std::regex memoryRegionEntryRegex("([0-9a-fA-F]+)\\-([0-9a-fA-F]+)\\s+((?:r|w|x|p|s|\\-)+)\\s+([0-9a-fA-F]+)");

void DarlingServer::Process::memoryRegionInfo(uintptr_t address, uintptr_t& startAddress, uint64_t& pageCount, int& protection, uint64_t& mapOffset, bool& shared) const {
	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	uintptr_t endAddress;

	while (std::getline(file, line)) {
		std::smatch match;

		if (!std::regex_search(line, match, memoryRegionEntryRegex)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		startAddress = std::stoul(match[1].str());
		endAddress = std::stoul(match[2].str());

		if (endAddress <= address || startAddress > address) {
			continue;
		}

		pageCount = (endAddress - startAddress) / sysconf(_SC_PAGESIZE);

		mapOffset = std::stoul(match[4].str());

		auto perms = match[3].str();

		protection = 0;

		if (perms.find('r') != std::string::npos) {
			protection |= PROT_READ;
		}
		if (perms.find('w') != std::string::npos) {
			protection |= PROT_WRITE;
		}
		if (perms.find('x') != std::string::npos) {
			protection |= PROT_EXEC;
		}

		shared = perms.find('s') != std::string::npos;

		return;
	}

	processLog.warning() << *this << ": Address " << std::hex << address << " not found in \"/proc/" << _pid << "/maps\"";
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
