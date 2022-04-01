#ifndef _DARLINGSERVER_DUCT_TAPE_MEMORY_H_
#define _DARLINGSERVER_DUCT_TAPE_MEMORY_H_

#include <stdint.h>
#include <mach/vm_types.h>
#include <os/refcnt.h>
#include <sys/tree.h>

#include <darlingserver/duct-tape/locks.h>

struct dtape_task;

typedef struct dtape_map_shared_descriptor {
	os_refcnt_t refcount;
	int memfd;
	uint64_t size;
} dtape_map_shared_descriptor_t;

typedef struct dtape_map_shared_entry {
	RB_ENTRY(dtape_map_shared_entry) link;
	uint64_t address;
	uint64_t size;
	uint64_t page_offset;
	dtape_map_shared_descriptor_t* descriptor;
} dtape_map_shared_entry_t;

typedef RB_HEAD(dtape_map_shared_entry_head, dtape_map_shared_entry) dtape_map_shared_entry_head_t;

struct _vm_map {
	uint32_t dtape_page_shift;
	uint64_t max_offset;
	os_refcnt_t map_refcnt;
	struct dtape_task* dtape_task;
	dtape_map_shared_entry_head_t shared_entries;
	dtape_mutex_t shared_entry_lock;
};

typedef struct _vm_map dtape_map_t;

#define VM_MAP_PAGE_SHIFT(map) ((map) ? (map)->dtape_page_shift : PAGE_SHIFT)

struct vm_map_header {

};

struct vm_map_copy {
	int type;
	uint64_t offset;
	uint64_t size;
	union {
		struct vm_map_header hdr;
		vm_object_t object;
		void* kdata;
	} c_u;
	char dtape_copy_data[];
};

#define cpy_hdr c_u.hdr

#define cpy_object c_u.object
#define cpy_kdata c_u.kdata

#define VM_MAP_COPY_ENTRY_LIST 1
#define VM_MAP_COPY_OBJECT 2
#define VM_MAP_COPY_KERNEL_BUFFER 3

void dtape_memory_init(void);
vm_map_t dtape_vm_map_create(struct dtape_task* task);
void dtape_vm_map_destroy(vm_map_t map);

#endif // _DARLINGSERVER_DUCT_TAPE_MEMORY_H_
