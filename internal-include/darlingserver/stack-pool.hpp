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

#ifndef _DARLINGSERVER_STACK_POOL_HPP_
#define _DARLINGSERVER_STACK_POOL_HPP_

#include <stddef.h>

#include <vector>
#include <mutex>

namespace DarlingServer {
	class StackPool {
	public:
		struct Stack {
			/**
			 * This is the lowest address of the stack in memory.
			 */
			void* base = nullptr;

			/**
			 * The size of this stack, in bytes.
			 */
			size_t size = 0;

			/**
			 * Whether or not this stack uses guard pages at the top and bottom of the stack.
			 */
			bool usesGuardPages = false;

			bool isValid() const;
			explicit operator bool() const;
		};

	private:
		size_t _idleStackCount;
		size_t _stackSize;
		bool _useGuardPages;
		std::vector<void*> _stacks;
		std::mutex _mutex;

		static void* _allocate(size_t stackSize, bool useGuardPages);
		static void _free(void* stack, size_t stackSize, bool useGuardPages);

	public:
		StackPool(size_t idleStackCount, size_t stackSize, bool useGuardPages);

		void allocate(Stack& stack);
		void free(Stack& stack);
	};
};

#endif // _DARLINGSERVER_STACK_POOL_HPP_
