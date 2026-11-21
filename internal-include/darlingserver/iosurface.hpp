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

#ifndef _DARLINGSERVER_IOSURFACE_HPP_
#define _DARLINGSERVER_IOSURFACE_HPP_

#include <darlingserver/rpc-supplement.h>

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <unordered_map>

namespace DarlingServer {
	/**
	 * The surfaces of the IOSurface service (see "IOSurface service" in rpc-supplement.h).
	 *
	 * Processes are named by their ID; finding out which process is calling is up to the caller.
	 * Every method returns 0 or a negative errno value. Descriptors passed in are borrowed; those
	 * passed out are new and belong to the caller.
	 */
	class IOSurfaceRegistry {
	public:
		using ProcessID = pid_t;

		struct State {
			uint32_t holders;
			uint32_t memoryUsers;
			uint32_t flags;
		};

	private:
		struct Holder {
			uint32_t references = 0;
			uint32_t usage = 0;
		};

		struct Surface {
			uint32_t id = 0;
			dev_t device = 0;
			ino_t inode = 0;
			int memory = -1;
			uint32_t flags = 0;
			uint32_t counterOffset = 0;
			// the last value written to the counter, or UINT32_MAX before the first write
			uint32_t publishedMemoryUsers = UINT32_MAX;
			int gpuBuffer = -1;
			dserver_iosurface_gpu_buffer_t gpuBufferInfo {};
			std::unordered_map<ProcessID, Holder> holders;
		};

		mutable std::mutex _mutex;
		std::map<uint32_t, Surface> _surfaces;
		uint32_t _lastID = 0;

		Surface* _find(uint32_t id);
		const Surface* _find(uint32_t id) const;
		Surface* _findByIdentity(dev_t device, ino_t inode);
		uint32_t _newID(uint32_t hint);
		static uint32_t _memoryUsers(const Surface& surface);
		static void _publish(Surface& surface);
		void _drop(std::map<uint32_t, Surface>::iterator it);

	public:
		IOSurfaceRegistry() = default;
		~IOSurfaceRegistry();

		IOSurfaceRegistry(const IOSurfaceRegistry&) = delete;
		IOSurfaceRegistry& operator=(const IOSurfaceRegistry&) = delete;

		static IOSurfaceRegistry& sharedInstance();

		int retain(ProcessID process, int memory, uint32_t idHint, uint32_t flags, uint32_t counterOffset, uint32_t* surfaceID);
		int release(ProcessID process, uint32_t surfaceID);
		int lookup(ProcessID process, uint32_t surfaceID, int* memory) const;
		int publishGPUBuffer(ProcessID process, uint32_t surfaceID, int buffer, const dserver_iosurface_gpu_buffer_t& info, int* published, dserver_iosurface_gpu_buffer_t* publishedInfo);
		int copyGPUBuffer(ProcessID process, uint32_t surfaceID, int* buffer, dserver_iosurface_gpu_buffer_t* info) const;
		int setUsage(ProcessID process, uint32_t surfaceID, uint32_t usage);
		int getState(uint32_t surfaceID, State* state) const;

		/**
		 * Drops every hold of a process that exited or exec'd.
		 */
		void forgetProcess(ProcessID process);

		/**
		 * The number of surfaces some process holds.
		 */
		size_t surfaceCount() const;
	};
};

#endif // _DARLINGSERVER_IOSURFACE_HPP_
