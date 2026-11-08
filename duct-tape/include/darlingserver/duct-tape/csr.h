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

#ifndef _DARLINGSERVER_DUCT_TAPE_CSR_H_
#define _DARLINGSERVER_DUCT_TAPE_CSR_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Whether @p config only contains flags that XNU's `<sys/csr.h>` defines (`CSR_VALID_FLAGS`).
 */
bool dtape_csr_config_is_valid(uint32_t config);

/**
 * The configuration in effect when none has been set: the flags `csrutil disable` sets (`CSR_DISABLE_FLAGS`).
 */
uint32_t dtape_csr_default_config(void);

/**
 * Whether @p config lets task_for_pid() reach processes that System Integrity Protection would
 * otherwise protect (`CSR_ALLOW_TASK_FOR_PID`).
 */
bool dtape_csr_allows_task_for_pid(uint32_t config);

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_CSR_H_
