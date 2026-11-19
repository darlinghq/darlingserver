/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Lubos Dolezel
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

#include <darlingserver/iosurface.hpp>

#include <cerrno>
#include <cstring>
#include <iterator>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

DarlingServer::IOSurfaceRegistry& DarlingServer::IOSurfaceRegistry::sharedInstance() {
	static IOSurfaceRegistry registry;
	return registry;
};

DarlingServer::IOSurfaceRegistry::~IOSurfaceRegistry() {
	for (auto& [id, surface]: _surfaces) {
		if (surface.memory >= 0) {
			close(surface.memory);
		}
		if (surface.gpuBuffer >= 0) {
			close(surface.gpuBuffer);
		}
	}
};

DarlingServer::IOSurfaceRegistry::Surface* DarlingServer::IOSurfaceRegistry::_find(uint32_t id) {
	auto it = _surfaces.find(id);
	return (it == _surfaces.end()) ? nullptr : &it->second;
};

const DarlingServer::IOSurfaceRegistry::Surface* DarlingServer::IOSurfaceRegistry::_find(uint32_t id) const {
	auto it = _surfaces.find(id);
	return (it == _surfaces.end()) ? nullptr : &it->second;
};

DarlingServer::IOSurfaceRegistry::Surface* DarlingServer::IOSurfaceRegistry::_findByIdentity(dev_t device, ino_t inode) {
	for (auto& [id, surface]: _surfaces) {
		if (surface.device == device && surface.inode == inode) {
			return &surface;
		}
	}
	return nullptr;
};

// IDs are never 0 and are not reused while a surface has them; after wrapping around, the next
// free one is taken
uint32_t DarlingServer::IOSurfaceRegistry::_newID(uint32_t hint) {
	if (hint != 0 && _surfaces.find(hint) == _surfaces.end()) {
		return hint;
	}
	do {
		++_lastID;
	} while (_lastID == 0 || _surfaces.find(_lastID) != _surfaces.end());
	return _lastID;
};

// holders that have not imported the GPU buffer, or that use the memory as well
uint32_t DarlingServer::IOSurfaceRegistry::_memoryUsers(const Surface& surface) {
	uint32_t count = 0;
	for (auto& [process, holder]: surface.holders) {
		if (!(holder.usage & DSERVER_IOSURFACE_USAGE_IMPORTED_BUFFER) || (holder.usage & DSERVER_IOSURFACE_USAGE_USES_MEMORY)) {
			++count;
		}
	}
	return count;
};

// writes the number of memory users into the surface's memory object when it changed. pwrite and
// not a mapping: a holder may shrink the object at any time, which must not fault the server.
void DarlingServer::IOSurfaceRegistry::_publish(Surface& surface) {
	if (surface.counterOffset == 0) {
		return;
	}
	uint32_t value = _memoryUsers(surface);
	if (value == surface.publishedMemoryUsers) {
		return;
	}
	if (pwrite(surface.memory, &value, sizeof(value), surface.counterOffset) == sizeof(value)) {
		surface.publishedMemoryUsers = value;
	}
};

void DarlingServer::IOSurfaceRegistry::_drop(std::map<uint32_t, Surface>::iterator it) {
	Surface& surface = it->second;
	if (surface.memory >= 0) {
		close(surface.memory);
	}
	if (surface.gpuBuffer >= 0) {
		close(surface.gpuBuffer);
	}
	_surfaces.erase(it);
};

int DarlingServer::IOSurfaceRegistry::retain(ProcessID process, int memory, uint32_t idHint, uint32_t flags, uint32_t counterOffset, uint32_t* surfaceID) {
	struct stat info;
	if (memory < 0 || fstat(memory, &info) != 0) {
		return -EBADF;
	}
	// memory files and POSIX shared memory objects are regular files
	if (!S_ISREG(info.st_mode)) {
		return -EINVAL;
	}
	if (flags & ~DSERVER_IOSURFACE_GLOBAL) {
		return -EINVAL;
	}
	if (counterOffset != 0 && (counterOffset % sizeof(uint32_t) != 0 || counterOffset > DSERVER_IOSURFACE_COUNTER_LIMIT - sizeof(uint32_t))) {
		return -EINVAL;
	}

	std::unique_lock lock(_mutex);

	Surface* surface = _findByIdentity(info.st_dev, info.st_ino);
	if (!surface) {
		int copy = fcntl(memory, F_DUPFD_CLOEXEC, 0);
		if (copy < 0) {
			return -errno;
		}
		uint32_t id = _newID(idHint);
		surface = &_surfaces[id];
		surface->id = id;
		surface->device = info.st_dev;
		surface->inode = info.st_ino;
		surface->memory = copy;
		surface->flags = flags;
		surface->counterOffset = counterOffset;
	}

	++surface->holders[process].references;
	_publish(*surface);
	*surfaceID = surface->id;
	return 0;
};

int DarlingServer::IOSurfaceRegistry::release(ProcessID process, uint32_t surfaceID) {
	std::unique_lock lock(_mutex);

	auto it = _surfaces.find(surfaceID);
	if (it == _surfaces.end()) {
		return -ENOENT;
	}
	auto holder = it->second.holders.find(process);
	if (holder == it->second.holders.end()) {
		return -ENOENT;
	}
	if (--holder->second.references == 0) {
		it->second.holders.erase(holder);
		if (it->second.holders.empty()) {
			_drop(it);
			return 0;
		}
		_publish(it->second);
	}
	return 0;
};

int DarlingServer::IOSurfaceRegistry::lookup(ProcessID process, uint32_t surfaceID, int* memory) const {
	std::unique_lock lock(_mutex);

	const Surface* surface = _find(surfaceID);
	// a surface that is not global is found only by processes that already hold it
	if (!surface || (!(surface->flags & DSERVER_IOSURFACE_GLOBAL) && surface->holders.find(process) == surface->holders.end())) {
		return -ENOENT;
	}
	int copy = fcntl(surface->memory, F_DUPFD_CLOEXEC, 0);
	if (copy < 0) {
		return -errno;
	}
	*memory = copy;
	return 0;
};

static bool validGPUBufferInfo(const dserver_iosurface_gpu_buffer_t& info) {
	if (info.fourcc == 0 || info.width == 0 || info.height == 0 || info.stride == 0 || info.reserved != 0) {
		return false;
	}
	size_t length = strnlen(info.render_node, sizeof(info.render_node));
	return length > 0 && length < sizeof(info.render_node);
};

int DarlingServer::IOSurfaceRegistry::publishGPUBuffer(ProcessID process, uint32_t surfaceID, int buffer, const dserver_iosurface_gpu_buffer_t& info, int* published, dserver_iosurface_gpu_buffer_t* publishedInfo) {
	struct stat bufferInfo;
	if (buffer < 0 || fstat(buffer, &bufferInfo) != 0) {
		return -EBADF;
	}
	if (!validGPUBufferInfo(info)) {
		return -EINVAL;
	}

	std::unique_lock lock(_mutex);

	Surface* surface = _find(surfaceID);
	if (!surface) {
		return -ENOENT;
	}
	auto holder = surface->holders.find(process);
	if (holder == surface->holders.end()) {
		return -EPERM;
	}

	if (surface->gpuBuffer < 0) {
		int copy = fcntl(buffer, F_DUPFD_CLOEXEC, 0);
		if (copy < 0) {
			return -errno;
		}
		surface->gpuBuffer = copy;
		surface->gpuBufferInfo = info;
	}

	int copy = fcntl(surface->gpuBuffer, F_DUPFD_CLOEXEC, 0);
	if (copy < 0) {
		return -errno;
	}
	holder->second.usage |= DSERVER_IOSURFACE_USAGE_IMPORTED_BUFFER;
	_publish(*surface);
	*published = copy;
	*publishedInfo = surface->gpuBufferInfo;
	return 0;
};

int DarlingServer::IOSurfaceRegistry::copyGPUBuffer(ProcessID process, uint32_t surfaceID, int* buffer, dserver_iosurface_gpu_buffer_t* info) const {
	std::unique_lock lock(_mutex);

	const Surface* surface = _find(surfaceID);
	if (!surface) {
		return -ENOENT;
	}
	if (surface->holders.find(process) == surface->holders.end()) {
		return -EPERM;
	}
	if (surface->gpuBuffer < 0) {
		return -ENOENT;
	}
	int copy = fcntl(surface->gpuBuffer, F_DUPFD_CLOEXEC, 0);
	if (copy < 0) {
		return -errno;
	}
	*buffer = copy;
	*info = surface->gpuBufferInfo;
	return 0;
};

int DarlingServer::IOSurfaceRegistry::setUsage(ProcessID process, uint32_t surfaceID, uint32_t usage) {
	if (usage & ~(DSERVER_IOSURFACE_USAGE_IMPORTED_BUFFER | DSERVER_IOSURFACE_USAGE_USES_MEMORY)) {
		return -EINVAL;
	}

	std::unique_lock lock(_mutex);

	Surface* surface = _find(surfaceID);
	if (!surface) {
		return -ENOENT;
	}
	auto holder = surface->holders.find(process);
	if (holder == surface->holders.end()) {
		return -EPERM;
	}
	holder->second.usage |= usage;
	_publish(*surface);
	return 0;
};

int DarlingServer::IOSurfaceRegistry::getState(uint32_t surfaceID, State* state) const {
	std::unique_lock lock(_mutex);

	const Surface* surface = _find(surfaceID);
	if (!surface) {
		return -ENOENT;
	}
	state->holders = static_cast<uint32_t>(surface->holders.size());
	state->memoryUsers = _memoryUsers(*surface);
	state->flags = ((surface->flags & DSERVER_IOSURFACE_GLOBAL) ? DSERVER_IOSURFACE_STATE_GLOBAL : 0)
		| ((surface->gpuBuffer >= 0) ? DSERVER_IOSURFACE_STATE_HAS_GPU_BUFFER : 0);
	return 0;
};

void DarlingServer::IOSurfaceRegistry::forgetProcess(ProcessID process) {
	std::unique_lock lock(_mutex);

	for (auto it = _surfaces.begin(); it != _surfaces.end();) {
		auto next = std::next(it);
		if (it->second.holders.erase(process) != 0) {
			if (it->second.holders.empty()) {
				_drop(it);
			} else {
				_publish(it->second);
			}
		}
		it = next;
	}
};

size_t DarlingServer::IOSurfaceRegistry::surfaceCount() const {
	std::unique_lock lock(_mutex);
	return _surfaces.size();
};
