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

#include <fstream>

DarlingServer::Process::Process(ID id, NSID nsid):
	_pid(id),
	_nspid(nsid)
{
	_pidfd = syscall(SYS_pidfd_open, _pid, 0);
	if (_pidfd < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to open pidfd for process");
	}

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

	// NOTE: see thread.cpp for why it's okay to use `this` here
	_dtapeTask = dtape_task_create(parentProcess ? parentProcess->_dtapeTask : nullptr, _nspid, this);
};

DarlingServer::Process::Process(KernelProcessConstructorTag tag):
	_pid(-1),
	_nspid(0),
	_pidfd(-1)
{
	_dtapeTask = dtape_task_create(nullptr, _nspid, this);
};

DarlingServer::Process::~Process() {
	close(_pidfd);

	_unregisterThreads();

	dtape_task_destroy(_dtapeTask);
};

void DarlingServer::Process::_unregisterThreads() {
	std::unique_lock lock(_rwlock);
	while (!_threads.empty()) {
		auto thread = _threads.back().lock();
		lock.unlock();
		if (thread) {
			thread->_process = std::weak_ptr<Process>();
			threadRegistry().unregisterEntry(thread);
		}
		lock.lock();
		_threads.pop_back();
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

	for (auto& maybeThread: _threads) {
		if (auto thread = maybeThread.lock()) {
			result.push_back(thread);
		}
	}

	return result;
};

std::string DarlingServer::Process::vchrootPath() const {
	std::shared_lock lock(_rwlock);
	return _vchrootPath;
};

void DarlingServer::Process::setVchrootPath(std::string path) {
	std::unique_lock lock(_rwlock);
	_vchrootPath = path;
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
