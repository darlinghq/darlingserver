/**
 * This file is part of Darling.
 *
 * Copyright (C) 2022 Darling developers
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

#include <darlingserver/stack-pool.hpp>

#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#if DSERVER_ASAN
	#include <sanitizer/asan_interface.h>
#endif

bool DarlingServer::StackPool::Stack::isValid() const {
	return base != nullptr && size != 0;
};

DarlingServer::StackPool::Stack::operator bool() const {
	return isValid();
};

DarlingServer::StackPool::StackPool(size_t idleStackCount, size_t stackSize, bool useGuardPages):
	_idleStackCount(idleStackCount),
	_stackSize(stackSize),
	_useGuardPages(useGuardPages)
{
	for (size_t i = 0; i < _idleStackCount; ++i) {
		_stacks.push_back(_allocate(_stackSize, _useGuardPages));
	}
};

void* DarlingServer::StackPool::_allocate(size_t stackSize, bool useGuardPages) {
	void* stack = NULL;
	size_t pageSize = sysconf(_SC_PAGESIZE);

	if (useGuardPages) {
		stack = mmap(NULL, stackSize + pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	} else {
		stack = mmap(NULL, stackSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	}

	if (stack == MAP_FAILED) {
		throw std::system_error(errno, std::generic_category());
	}

	if (useGuardPages) {
		mprotect(stack, pageSize, PROT_NONE);
		stack = (char*)stack + pageSize;
		mprotect((char*)stack + stackSize, pageSize, PROT_NONE);
	}

	return stack;
};

void DarlingServer::StackPool::_free(void* stack, size_t stackSize, bool useGuardPages) {
	size_t pageSize = sysconf(_SC_PAGESIZE);

	if (useGuardPages) {
		if (munmap((char*)stack - pageSize, stackSize + pageSize * 2) < 0) {
			throw std::system_error(errno, std::generic_category());
		}
	} else {
		if (munmap(stack, stackSize) < 0) {
			throw std::system_error(errno, std::generic_category());
		}
	}
};

void DarlingServer::StackPool::allocate(Stack& stack) {
	std::scoped_lock lock(_mutex);

	if (_stacks.size() > 0) {
		// great, we can use one from the pool

		stack.base = _stacks.back();
		stack.size = _stackSize;
		stack.usesGuardPages = _useGuardPages;

		_stacks.pop_back();
	} else {
		// we don't have any available, so we have to allocate one now
		stack.base = _allocate(_stackSize, _useGuardPages);
		stack.size = _stackSize;
		stack.usesGuardPages = _useGuardPages;
	}
};

void DarlingServer::StackPool::free(Stack& stack) {
	std::scoped_lock lock(_mutex);

	// for now, we only support a single standard stack size and guard page usage
	assert(stack.size == _stackSize);
	assert(stack.usesGuardPages == _useGuardPages);

	if (_stacks.size() > _idleStackCount) {
		// we have more stacks than we want;
		// just free this one
		_free(stack.base, stack.size, stack.usesGuardPages);
	} else {
		// let's keep this one around
		_stacks.push_back(stack.base);

#if DSERVER_ASAN
		// make sure to unpoison this memory region, since it might be re-used later
		__asan_unpoison_memory_region(stack.base, stack.size);
#endif
	}

	stack = Stack();
};
