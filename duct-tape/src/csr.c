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

#include <darlingserver/duct-tape/csr.h>

#include <sys/csr.h>

bool dtape_csr_config_is_valid(uint32_t config) {
	return (config & ~(uint32_t)CSR_VALID_FLAGS) == 0;
};

uint32_t dtape_csr_default_config(void) {
	return CSR_DISABLE_FLAGS;
};

bool dtape_csr_allows_task_for_pid(uint32_t config) {
	return (config & CSR_ALLOW_TASK_FOR_PID) != 0;
};
