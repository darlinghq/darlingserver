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

#ifndef _DARLINGSERVER_PROCMAP_QUERY_H_
#define _DARLINGSERVER_PROCMAP_QUERY_H_

#include <sys/ioctl.h>
#include <linux/fs.h>

// PROCMAP_QUERY (Linux 6.11) looks up a single VMA of another process through its `/proc/<pid>/maps`
// descriptor. Older userspace headers lack it; its ABI is fixed, so define it here. On an older running
// kernel the ioctl fails with ENOTTY and the text of `/proc/<pid>/maps` is parsed instead.
#ifndef PROCMAP_QUERY
#include <linux/types.h>
enum procmap_query_flags {
	PROCMAP_QUERY_VMA_READABLE = 0x01,
	PROCMAP_QUERY_VMA_WRITABLE = 0x02,
	PROCMAP_QUERY_VMA_EXECUTABLE = 0x04,
	PROCMAP_QUERY_VMA_SHARED = 0x08,
	PROCMAP_QUERY_COVERING_OR_NEXT_VMA = 0x10,
	PROCMAP_QUERY_FILE_BACKED_VMA = 0x20,
};
struct procmap_query {
	__u64 size;
	__u64 query_flags;
	__u64 query_addr;
	__u64 vma_start;
	__u64 vma_end;
	__u64 vma_flags;
	__u64 vma_page_size;
	__u64 vma_offset;
	__u64 inode;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 vma_name_size;
	__u32 build_id_size;
	__u64 vma_name_addr;
	__u64 build_id_addr;
};
#define PROCMAP_QUERY _IOWR('f', 17, struct procmap_query)
#endif

#endif // _DARLINGSERVER_PROCMAP_QUERY_H_
