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

#ifndef _DARLINGSERVER_CODESIGN_MACHO_FORMAT_H_
#define _DARLINGSERVER_CODESIGN_MACHO_FORMAT_H_

/*
 * The few Mach-O file format values the signature parser needs.
 *
 * They have the values and meaning of the same-named constants in the public
 * `<mach-o/loader.h>` and `<mach-o/fat.h>`. Those headers (imported under
 * duct-tape/xnu/EXTERNAL_HEADERS) pull in XNU's `<mach/machine.h>`, whose type
 * definitions clash with the host C library, so they cannot be included here.
 * The code signature constants, in contrast, come straight from `<kern/cs_blobs.h>`.
 */

/* <mach-o/loader.h> */
#define DC_MH_MAGIC            0xfeedfaceu
#define DC_MH_MAGIC_64         0xfeedfacfu
#define DC_MACH_HEADER_SIZE    28u /* sizeof(struct mach_header) */
#define DC_MACH_HEADER_64_SIZE 32u /* sizeof(struct mach_header_64) */
#define DC_LC_CODE_SIGNATURE   0x1du
#define DC_LINKEDIT_DATA_COMMAND_SIZE 16u /* sizeof(struct linkedit_data_command) */

/* <mach-o/fat.h>; the fat header and arch table are always big-endian */
#define DC_FAT_MAGIC           0xcafebabeu
#define DC_FAT_MAGIC_64        0xcafebabfu
#define DC_FAT_HEADER_SIZE     8u  /* sizeof(struct fat_header) */
#define DC_FAT_ARCH_SIZE       20u /* sizeof(struct fat_arch) */
#define DC_FAT_ARCH_64_SIZE    32u /* sizeof(struct fat_arch_64) */

#endif // _DARLINGSERVER_CODESIGN_MACHO_FORMAT_H_
