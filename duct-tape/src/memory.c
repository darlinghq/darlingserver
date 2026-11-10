#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>

#include <stdlib.h>
#include <sys/errno.h>

#include <mach_debug/mach_debug.h>

struct zone {
	const char* name;
	vm_size_t size;
};

// stub
struct kalloc_heap KHEAP_DEFAULT[1];
// stub
struct kalloc_heap KHEAP_DATA_BUFFERS[1];

// stub
vm_size_t kalloc_max_prerounded = 0;

void* calloc(size_t count, size_t size);
void* aligned_alloc(size_t alignment, size_t size);

void* mmap(void* addr, size_t length, int prot, int flags, int fd, long int offset);
int munmap(void* addr, size_t length);
long sysconf(int name);

int memfd_create(const char *name, unsigned int flags);

int close(int fd);
int ftruncate(int fd, off_t length);

#define MAP_ANONYMOUS 0x20
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02

#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_FAILED ((void*)-1)

#define _SC_PAGESIZE 30

#define MFD_CLOEXEC 0x1

void dtape_memory_init(void) {

};

static uint64_t dtape_byte_count_to_page_count_round_up(uint64_t byte_count) {
	return (byte_count + (sysconf(_SC_PAGESIZE) - 1)) / sysconf(_SC_PAGESIZE);
};

static uint64_t dtape_byte_count_to_page_count_round_down(uint64_t byte_count) {
	return byte_count / sysconf(_SC_PAGESIZE);
};

static int dtape_map_shared_entry_compare(dtape_map_shared_entry_t* first, dtape_map_shared_entry_t* second) {
	if (first->address < second->address) {
		return -1;
	} else if (first->address > second->address) {
		return 1;
	} else {
		return 0;
	}
};

RB_PROTOTYPE_SC(static, dtape_map_shared_entry_head, dtape_map_shared_entry, link, dtape_map_shared_entry_compare);
RB_GENERATE(dtape_map_shared_entry_head, dtape_map_shared_entry, link, dtape_map_shared_entry_compare);

vm_map_t dtape_vm_map_create(struct dtape_task* task) {
	vm_map_t map = malloc(sizeof(struct _vm_map));
	if (!map) {
		return map;
	}

	os_ref_init(&map->map_refcnt, NULL);

	map->max_offset = MACH_VM_MAX_ADDRESS;
	map->dtape_page_shift = __builtin_ctzl(sysconf(_SC_PAGESIZE));

	map->dtape_task = task;

	RB_INIT(&map->shared_entries);
	dtape_mutex_init(&map->shared_entry_lock);

	return map;
};

static dtape_map_shared_descriptor_t* dtape_map_shared_descriptor_create(int memfd, uint64_t size) {
	dtape_map_shared_descriptor_t* desc = malloc(sizeof(dtape_map_shared_descriptor_t));
	if (!desc) {
		return NULL;
	}

	os_ref_init(&desc->refcount, NULL);

	desc->memfd = memfd;
	desc->size = size;

	return desc;
};

static void dtape_map_shared_descriptor_retain(dtape_map_shared_descriptor_t* desc) {
	os_ref_retain(&desc->refcount);
};

static void dtape_map_shared_descriptor_release(dtape_map_shared_descriptor_t* desc) {
	if (os_ref_release(&desc->refcount) != 0) {
		return;
	}

	close(desc->memfd);
	free(desc);
};

static dtape_map_shared_entry_t* dtape_map_shared_entry_create(uint64_t address, uint64_t size, uint64_t page_offset, dtape_map_shared_descriptor_t* descriptor) {
	dtape_map_shared_entry_t* shared_entry = malloc(sizeof(dtape_map_shared_entry_t));
	if (!shared_entry) {
		return NULL;
	}

	shared_entry->address = address;
	shared_entry->size = size;
	shared_entry->page_offset = page_offset;
	shared_entry->descriptor = descriptor;

	dtape_map_shared_descriptor_retain(descriptor);

	return shared_entry;
};

static void dtape_map_shared_entry_destroy(dtape_map_shared_entry_t* shared_entry) {
	dtape_map_shared_descriptor_release(shared_entry->descriptor);
	free(shared_entry);
};

static void dtape_map_insert_shared_entry_locked(dtape_map_t* map, dtape_map_shared_entry_t* shared_entry) {
	RB_INSERT(dtape_map_shared_entry_head, &map->shared_entries, shared_entry);
};

static void dtape_map_insert_shared_entry(dtape_map_t* map, dtape_map_shared_entry_t* shared_entry) {
	dtape_mutex_lock(&map->shared_entry_lock);
	dtape_map_insert_shared_entry_locked(map, shared_entry);
	dtape_mutex_unlock(&map->shared_entry_lock);
};

/**
 * Returns entries in-order.
 * If the number of entries returned is equal to the space provided and the address of the last entry returned still falls
 * within the target region, there may be additional entries intersecting the region. You can call this function again with
 * the address just after the last entry to continue searching.
 */
static size_t dtape_map_find_shared_entries_locked(dtape_map_t* map, uint64_t address, uint64_t size, dtape_map_shared_entry_t** out_entries, size_t entry_count) {
	dtape_map_shared_entry_t* entry;
	size_t count = 0;

	if (entry_count == 0) {
		return count;
	}

	RB_FOREACH(entry, dtape_map_shared_entry_head, &map->shared_entries) {
		// entries and the region are half-open ranges: an entry that ends where the region starts,
		// or starts where it ends, is only adjacent to it
		if (entry->address + entry->size <= address || entry->address >= address + size) {
			continue;
		}

		out_entries[count++] = entry;

		if (count == entry_count) {
			break;
		}
	}

	return count;
};

// TODO: we should have the process inform us when it unmaps a shared entry that we remapped;
//       right now, we only close the memfd when the process dies (so the memory is potentially in-use needlessly).

void dtape_vm_map_destroy(vm_map_t map) {
	if (os_ref_release(&map->map_refcnt) != 0) {
		panic("VM map still in-use at destruction");
	}

	dtape_map_shared_entry_t* entry;
	dtape_map_shared_entry_t* tmp;

	dtape_mutex_lock(&map->shared_entry_lock);
	RB_FOREACH_SAFE(entry, dtape_map_shared_entry_head, &map->shared_entries, tmp) {
		RB_REMOVE(dtape_map_shared_entry_head, &map->shared_entries, entry);
		dtape_map_shared_entry_destroy(entry);
	}
	dtape_mutex_unlock(&map->shared_entry_lock);

	free(map);
};

void vm_map_reference(vm_map_t map) {
	os_ref_retain(&map->map_refcnt);
};

void vm_map_deallocate(vm_map_t map) {
	os_ref_release_live(&map->map_refcnt);
};

// TODO: zone-based allocations could be optimized to not just use malloc

zone_t zone_create(const char* name, vm_size_t size, zone_create_flags_t flags) {
	zone_t zone = malloc(sizeof(struct zone));
	if (!zone) {
		return ZONE_NULL;
	}
	zone->name = name;
	zone->size = size;
	return zone;
};

void zdestroy(zone_t zone) {
	free(zone);
};

void* zalloc(zone_or_view_t zone_or_view) {
	return malloc(zone_or_view.zov_zone->size);
};

void* zalloc_flags(zone_or_view_t zone_or_view, zalloc_flags_t flags) {
	void* ptr = zalloc(zone_or_view);
	if (!ptr) {
		return ptr;
	}

	if (flags & Z_ZERO) {
		memset(ptr, 0, zone_or_view.zov_zone->size);
	}

	return ptr;
};

void (zfree)(zone_or_view_t zone_or_view, void* elem) {
	free(elem);
};

void zone_id_require(zone_id_t zone_id, vm_size_t elem_size, void* addr) {
	dtape_stub_safe();
};

void zone_require(zone_t zone, void* addr) {
	dtape_stub_safe();
};

zone_t zinit(vm_size_t size, vm_size_t max, vm_size_t alloc, const char* name) {
	return zone_create(name, size, 0);
};

void (kheap_free)(kalloc_heap_t kheap, void* addr, vm_size_t size) {
	free(addr);
};

void (kheap_free_addr)(kalloc_heap_t kheap, void* addr) {
	kheap_free(kheap, addr, 0);
};

void (kfree)(void* addr, vm_size_t size) {
	free(addr);
};

struct kalloc_result kalloc_ext(kalloc_heap_t kheap, vm_size_t req_size, zalloc_flags_t flags, vm_allocation_site_t* site) {
	if (flags & Z_ZERO) {
		return (struct kalloc_result) { .addr = calloc(1, req_size), .size = req_size };
	} else {
		return (struct kalloc_result) { .addr = malloc(req_size), .size = req_size };
	}
};

const char* zone_heap_name(zone_t zone) {
	dtape_stub_safe();
	return "";
};

const char* zone_name(zone_t zone) {
	return zone->name;
};

void* zalloc_permanent(vm_size_t size, vm_offset_t align_mask) {
	size_t power_of_2 = (sizeof(long long) * 8) - __builtin_clzll(align_mask);
	void* memory = aligned_alloc(1 << power_of_2, size);
	if (!memory) {
		return memory;
	}

	memset(memory, 0, sizeof(size));
	return memory;
};

void vm_page_free_reserve(int pages) {
	dtape_stub_safe();
};

kern_return_t kernel_memory_allocate(vm_map_t map, vm_offset_t* addrp, vm_size_t size, vm_offset_t mask, kma_flags_t flags, vm_tag_t tag) {
	void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED) {
		return KERN_FAILURE;
	}

	*addrp = (vm_offset_t)ptr;
	return KERN_SUCCESS;
};

kern_return_t vm_deallocate(vm_map_t map, vm_offset_t start, vm_size_t size) {
	return munmap((void*)start, size) == 0;
};

kern_return_t vm_allocate_kernel(vm_map_t map, vm_offset_t* addr, vm_size_t size, int flags, vm_tag_t tag) {
	mach_vm_offset_t tmp;
	kern_return_t status = mach_vm_allocate_kernel(map, &tmp, size, flags, tag);
	if (status == KERN_SUCCESS) {
		*addr = tmp;
	}
	return status;
};

kern_return_t kmem_alloc(vm_map_t map, vm_offset_t* addrp, vm_size_t size, vm_tag_t tag) {
	return kernel_memory_allocate(map, addrp, size, 0, 0, tag);
};

void kmem_free(vm_map_t map, vm_offset_t addr, vm_size_t size) {
	vm_deallocate(map, addr, size);
};

kern_return_t copyoutmap(vm_map_t map, void* fromdata, vm_map_address_t toaddr, vm_size_t length) {
	if (map == kernel_map) {
		memmove((void*)toaddr, fromdata, length);
		return KERN_SUCCESS;
	} else {
		return dtape_hooks->task_write_memory(map->dtape_task->context, toaddr, fromdata, length) ? KERN_SUCCESS : KERN_FAILURE;
	}
};

kern_return_t copyinmap(vm_map_t map, vm_map_offset_t fromaddr, void* todata, vm_size_t length) {
	if (map == kernel_map) {
		memmove(todata, (const void*)fromaddr, length);
		return KERN_SUCCESS;
	} else {
		return dtape_hooks->task_read_memory(map->dtape_task->context, fromaddr, todata, length) ? KERN_SUCCESS : KERN_FAILURE;
	}
};

int (copyin)(const user_addr_t user_addr, void* kernel_addr, vm_size_t nbytes) {
	return (copyinmap(current_map(), user_addr, kernel_addr, nbytes) == KERN_SUCCESS) ? 0 : EFAULT;
};

int (copyout)(const void* kernel_addr, user_addr_t user_addr, vm_size_t nbytes) {
	// it doesn't actually modify kernel_addr
	return (copyoutmap(current_map(), (void*)kernel_addr, user_addr, nbytes) == KERN_SUCCESS) ? 0 : EFAULT;
};

#ifndef copyinmsg
int copyinmsg(const user_addr_t user_addr, char* kernel_addr, mach_msg_size_t nbytes) {
	return (copyin)(user_addr, kernel_addr, nbytes);
};
#endif

#ifndef copyoutmsg
int copyoutmsg(const char* kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes) {
	return (copyout)(kernel_addr, user_addr, nbytes);
};
#endif

kern_return_t kmem_suballoc(vm_map_t parent, vm_offset_t* addr, vm_size_t size, boolean_t pageable, int flags, vm_map_kernel_flags_t vmk_flags, vm_tag_t tag, vm_map_t* new_map) {
	// this is enough to satisfy ipc_init
	dtape_stub();
	*new_map = parent;
	return KERN_SUCCESS;
};

boolean_t vm_kernel_map_is_kernel(vm_map_t map) {
	return map == kernel_map || map == ipc_kernel_map;
};

void vm_map_copy_discard(vm_map_copy_t copy) {
	if (copy == VM_MAP_COPY_NULL) {
		return;
	}
	free(copy);
};

kern_return_t vm_map_copyin_common(vm_map_t src_map, vm_map_address_t src_addr, vm_map_size_t len, boolean_t src_destroy, boolean_t src_volatile, vm_map_copy_t* copy_result, boolean_t use_maxprot) {
	// XNU only performs a kernel buffer copy when the data is sufficiently small;
	// however, we always perform a kernel buffer copy just to make it easier for ourselves

	// this code has been adapted from vm_map_copyin_kernel_buffer() in osfmk/vm/vm_map.c

	kern_return_t kr;

	vm_map_copy_t copy = malloc(sizeof(struct vm_map_copy) + len);
	if (copy == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	copy->type = VM_MAP_COPY_KERNEL_BUFFER;
	copy->size = len;
	copy->offset = 0;
	copy->cpy_kdata = copy->dtape_copy_data;

	kr = copyinmap(src_map, src_addr, copy->cpy_kdata, (vm_size_t)len);
	if (kr != KERN_SUCCESS) {
		free(copy);
		return kr;
	}

	if (src_destroy) {
		vm_map_remove(src_map, vm_map_trunc_page(src_addr, VM_MAP_PAGE_MASK(src_map)), vm_map_round_page(src_addr + len, VM_MAP_PAGE_MASK(src_map)), 0);
	}

	*copy_result = copy;
	return KERN_SUCCESS;
};

static kern_return_t vm_map_copyout_kernel_buffer(vm_map_t map, vm_map_address_t* addr, vm_map_copy_t copy, vm_map_size_t copy_size, boolean_t overwrite, boolean_t consume_on_success) {
	kern_return_t kr = KERN_SUCCESS;

	if (!overwrite) {
		// we need to allocate memory for this copy

		if (map == kernel_map) {
			*addr = (uintptr_t)mmap(NULL, copy_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (*addr == (uintptr_t)MAP_FAILED) {
				return KERN_RESOURCE_SHORTAGE;
			}
		} else {
			*addr = dtape_hooks->task_allocate_pages(map->dtape_task->context, dtape_byte_count_to_page_count_round_up(copy_size), PROT_READ | PROT_WRITE, 0, 0);
			if (*addr == 0) {
				return KERN_RESOURCE_SHORTAGE;
			}
		}
	}

	if (copyoutmap(map, copy->cpy_kdata, *addr, (vm_size_t)copy_size)) {
		kr = KERN_INVALID_ADDRESS;
	}

	if (kr != KERN_SUCCESS) {
		if (!overwrite) {
			// clean up the space we allocate earlier
			vm_map_remove(map, vm_map_trunc_page(*addr, VM_MAP_PAGE_MASK(map)), vm_map_round_page((*addr + vm_map_round_page(copy_size, VM_MAP_PAGE_MASK(map))), VM_MAP_PAGE_MASK(map)), 0);
			*addr = 0;
		}
	} else {
		// copy was successful
		if (consume_on_success) {
			free(copy);
		}
	}

	return kr;
};

kern_return_t vm_map_copy_overwrite(vm_map_t dst_map, vm_map_offset_t dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size, boolean_t interruptible) {
	if (copy == VM_MAP_COPY_NULL) {
		return KERN_SUCCESS;
	}

	return vm_map_copyout_kernel_buffer(dst_map, &dst_addr, copy, copy->size, TRUE, TRUE);
};

kern_return_t vm_map_copyout_size(vm_map_t dst_map, vm_map_address_t* dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size) {
	if (copy == VM_MAP_COPY_NULL) {
		*dst_addr = 0;
		return KERN_SUCCESS;
	}

	if (copy->size != copy_size) {
		*dst_addr = 0;
		return KERN_FAILURE;
	}

	return vm_map_copyout_kernel_buffer(dst_map, dst_addr, copy, copy_size, FALSE, TRUE);
};

kern_return_t vm_map_copyout(vm_map_t dst_map, vm_map_address_t* dst_addr, vm_map_copy_t copy) {
	return vm_map_copyout_size(dst_map, dst_addr, copy, copy ? copy->size : 0);
};

boolean_t vm_map_copy_validate_size(vm_map_t dst_map, vm_map_copy_t copy, vm_map_size_t* size) {
	if (copy == VM_MAP_COPY_NULL) {
		return FALSE;
	}
	return *size == copy->size;
};

kern_return_t vm_map_remove(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, boolean_t flags) {
	if (map == kernel_map) {
		if (munmap((void*)start, end - start) < 0) {
			return KERN_FAILURE;
		}
		return KERN_SUCCESS;
	} else {
		if (dtape_hooks->task_free_pages(map->dtape_task->context, start, dtape_byte_count_to_page_count_round_down(end - start)) < 0) {
			return KERN_FAILURE;
		}
		return KERN_SUCCESS;
	}
};

kern_return_t mach_vm_allocate_kernel(vm_map_t map, mach_vm_offset_t* addr, mach_vm_size_t size, int flags, vm_tag_t tag) {
	if (map == kernel_map) {
		vm_offset_t tmp;
		kern_return_t kr = kernel_memory_allocate(map, &tmp, size, VM_MAP_PAGE_MASK(map), flags, tag);
		if (kr == KERN_SUCCESS) {
			*addr = tmp;
		}
		return kr;
	} else {
		// mach_vm_allocate_kernel allocates with default protection
		uintptr_t tmp = dtape_hooks->task_allocate_pages(map->dtape_task->context, dtape_byte_count_to_page_count_round_up(size), PROT_READ | PROT_WRITE, 0, 0);
		if (tmp == 0) {
			return KERN_RESOURCE_SHORTAGE;
		}
		*addr = tmp;
		return KERN_SUCCESS;
	}
};

static bool is_named_entry_port(ipc_port_t port) {
	return IP_VALID(port) && ip_kotype(port) == IKOT_NAMED_ENTRY;
};

kern_return_t mach_memory_entry_allocate(vm_named_entry_t* user_entry_p, ipc_port_t* user_handle_p) {
	vm_named_entry_t user_entry = kalloc(sizeof(*user_entry));
	if (user_entry == NULL) {
		return KERN_FAILURE;
	}
	bzero(user_entry, sizeof(*user_entry));

	named_entry_lock_init(user_entry);
	user_entry->backing.copy = NULL;
	user_entry->protection = VM_PROT_NONE;
	user_entry->ref_count = 1;
	user_entry->dtape_descriptor = NULL;

	ipc_port_t user_handle = ipc_kobject_alloc_port((ipc_kobject_t)user_entry, IKOT_NAMED_ENTRY, IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
	if (user_handle == IP_NULL) {
		named_entry_lock_destroy(user_entry);
		kfree(user_entry, sizeof(*user_entry));
		return KERN_FAILURE;
	}

	*user_entry_p = user_entry;
	*user_handle_p = user_handle;
	return KERN_SUCCESS;
};

static dtape_map_shared_descriptor_t* dtape_memory_entry_descriptor(ipc_port_t port) {
	if (!is_named_entry_port(port)) {
		return NULL;
	}
	vm_named_entry_t entry = (vm_named_entry_t)ip_get_kobject(port);
	return entry->dtape_descriptor;
};

// creates a zero-filled memfd of `size` bytes and, if asked, maps it in the server so it can be filled
static dtape_map_shared_descriptor_t* dtape_memory_entry_descriptor_create(uint64_t size, void** out_server_mapping) {
	int memfd = memfd_create("darling-memory-entry", MFD_CLOEXEC);
	if (memfd < 0) {
		return NULL;
	}

	if (ftruncate(memfd, size) < 0) {
		close(memfd);
		return NULL;
	}

	if (out_server_mapping) {
		*out_server_mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
		if (*out_server_mapping == MAP_FAILED) {
			close(memfd);
			return NULL;
		}
	}

	dtape_map_shared_descriptor_t* descriptor = dtape_map_shared_descriptor_create(memfd, size);
	if (!descriptor) {
		if (out_server_mapping) {
			munmap(*out_server_mapping, size);
		}
		close(memfd);
	}
	return descriptor;
};

static int dtape_linux_protection(vm_prot_t protection) {
	int prot = 0;
	if (protection & VM_PROT_READ) {
		prot |= PROT_READ;
	}
	if (protection & VM_PROT_WRITE) {
		prot |= PROT_WRITE;
	}
	if (protection & VM_PROT_EXECUTE) {
		prot |= PROT_EXEC;
	}
	return prot;
};

/*
 * Named entries made here are backed by a memfd (a dtape_map_shared_descriptor_t held by the entry).
 * Every mapping of the entry (mach_vm_map_external) maps that memfd shared, so all tasks that map it
 * see the same pages. Submaps, pagers and caching modes are not supported.
 */
kern_return_t _mach_make_memory_entry(vm_map_t target_map, memory_object_size_t* size, memory_object_offset_t offset, vm_prot_t permission, ipc_port_t* object_handle, ipc_port_t parent_handle) {
	const uint64_t page_mask = sysconf(_SC_PAGESIZE) - 1;
	kern_return_t kr = KERN_SUCCESS;
	dtape_map_shared_descriptor_t* descriptor = NULL;
	dtape_map_shared_descriptor_t* parent_descriptor = dtape_memory_entry_descriptor(parent_handle);
	vm_named_entry_t parent_entry = parent_descriptor ? (vm_named_entry_t)ip_get_kobject(parent_handle) : NULL;
	vm_named_entry_t user_entry = NULL;
	ipc_port_t user_handle = IP_NULL;
	vm_prot_t protections = permission & VM_PROT_ALL;
	bool mask_protections = (permission & VM_PROT_IS_MASK) != 0;
	bool use_data_addr = (permission & MAP_MEM_USE_DATA_ADDR) != 0;
	uint64_t entry_offset = 0;
	uint64_t offset_in_page = 0;
	uint64_t map_start;
	uint64_t map_size;
	void* staged = NULL;

	if ((permission & MAP_MEM_FLAGS_MASK) & ~MAP_MEM_FLAGS_ALL) {
		// unknown flags are rejected for forward compatibility, like XNU does
		return KERN_INVALID_VALUE;
	}

	if (permission & MAP_MEM_4K_DATA_ADDR) {
		// 4K-compatible data addresses are only meaningful on 16K-page systems
		return KERN_NOT_SUPPORTED;
	}

	if (offset + *size < offset) {
		return KERN_INVALID_ARGUMENT;
	}

	if (permission & MAP_MEM_ONLY) {
		// only changes the caching mode of an existing entry, which has no meaning here
		if (use_data_addr || !parent_entry) {
			return KERN_INVALID_ARGUMENT;
		}
		*object_handle = IP_NULL;
		return KERN_SUCCESS;
	}

	if (permission & MAP_MEM_NAMED_CREATE) {
		if (use_data_addr) {
			return KERN_INVALID_ARGUMENT;
		}
		if ((permission & MAP_MEM_PURGABLE) && !(permission & VM_PROT_WRITE)) {
			return KERN_INVALID_ARGUMENT;
		}

		map_start = offset & ~page_mask;
		map_size = ((offset + *size + page_mask) & ~page_mask) - map_start;
		if (map_size == 0) {
			*size = 0;
			*object_handle = IP_NULL;
			return KERN_SUCCESS;
		}

		// a new memfd is zero-filled, like a new VM object.
		// MAP_MEM_PURGABLE entries are never purged (nothing here can purge memory).
		descriptor = dtape_memory_entry_descriptor_create(map_size, NULL);
		if (!descriptor) {
			return KERN_RESOURCE_SHORTAGE;
		}
	} else if (parent_entry && !(permission & (MAP_MEM_VM_COPY | MAP_MEM_VM_SHARE | MAP_MEM_NAMED_REUSE))) {
		// a sub-range of an existing entry, sharing its object
		named_entry_lock(parent_entry);
		if (use_data_addr) {
			if (offset + *size + parent_entry->data_offset > parent_entry->size) {
				kr = KERN_INVALID_ARGUMENT;
			}
			map_start = (offset + parent_entry->data_offset) & ~page_mask;
			offset_in_page = offset + parent_entry->data_offset - map_start;
			map_size = ((offset + parent_entry->data_offset + *size + page_mask) & ~page_mask) - map_start;
		} else {
			map_start = offset & ~page_mask;
			map_size = ((offset + *size + page_mask) & ~page_mask) - map_start;
			if (offset + map_size > parent_entry->size) {
				kr = KERN_INVALID_ARGUMENT;
			}
		}
		if (mask_protections) {
			protections &= parent_entry->protection;
		}
		if (kr == KERN_SUCCESS && (protections & parent_entry->protection) != protections) {
			kr = KERN_PROTECTION_FAILURE;
		}
		entry_offset = parent_entry->offset + map_start;
		if (kr == KERN_SUCCESS) {
			descriptor = parent_entry->dtape_descriptor;
			dtape_map_shared_descriptor_retain(descriptor);
		}
		named_entry_unlock(parent_entry);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	} else {
		// an entry for a range of the target map's memory
		dtape_memory_region_info_t region_info;
		vm_prot_t region_protection = VM_PROT_NONE;

		if (target_map == VM_MAP_NULL) {
			return KERN_INVALID_TASK;
		}

		map_start = offset & ~page_mask;
		map_size = ((offset + *size + page_mask) & ~page_mask) - map_start;
		offset_in_page = use_data_addr ? offset - map_start : 0;
		if (map_size == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!dtape_hooks->task_get_memory_region_info(target_map->dtape_task->context, map_start, &region_info) ||
		    region_info.start_address > map_start) {
			return KERN_INVALID_ADDRESS;
		}
		if (region_info.start_address + region_info.page_count * (page_mask + 1) < map_start + map_size) {
			// a range spanning several host mappings is not supported
			return KERN_NOT_SUPPORTED;
		}
		if (region_info.protection & dtape_memory_protection_read) {
			region_protection |= VM_PROT_READ;
		}
		if (region_info.protection & dtape_memory_protection_write) {
			region_protection |= VM_PROT_WRITE;
		}
		if (region_info.protection & dtape_memory_protection_execute) {
			region_protection |= VM_PROT_EXECUTE;
		}
		if (mask_protections) {
			protections &= region_protection;
		}
		if ((protections & region_protection) != protections) {
			return KERN_PROTECTION_FAILURE;
		}

		if (!(permission & MAP_MEM_VM_COPY)) {
			// a range that is already shared (by mach_vm_remap) is shared through its existing object
			dtape_map_shared_entry_t* existing[8];
			size_t existing_count;

			dtape_mutex_lock(&target_map->shared_entry_lock);
			existing_count = dtape_map_find_shared_entries_locked(target_map, map_start, map_size, existing, sizeof(existing) / sizeof(*existing));
			for (size_t i = 0; i < existing_count; ++i) {
				dtape_map_shared_entry_t* candidate = existing[i];
				if (candidate->address + candidate->size <= map_start || candidate->address >= map_start + map_size) {
					// only adjacent
					continue;
				}
				if (candidate->address <= map_start && candidate->address + candidate->size >= map_start + map_size) {
					descriptor = candidate->descriptor;
					dtape_map_shared_descriptor_retain(descriptor);
					entry_offset = candidate->page_offset * (page_mask + 1) + (map_start - candidate->address);
				} else {
					kr = KERN_NOT_SUPPORTED;
				}
				break;
			}
			dtape_mutex_unlock(&target_map->shared_entry_lock);
			if (kr != KERN_SUCCESS) {
				return kr;
			}
		}

		if (!descriptor) {
			descriptor = dtape_memory_entry_descriptor_create(map_size, &staged);
			if (!descriptor) {
				return KERN_RESOURCE_SHORTAGE;
			}

			kr = copyinmap(target_map, map_start, staged, map_size);
			if (kr != KERN_SUCCESS) {
				goto out;
			}

			if (!(permission & MAP_MEM_VM_COPY) && !region_info.shared) {
				// The entry shares the range with the task, so the task's pages are replaced
				// by a shared mapping of the entry's object, keeping their contents and protection.
				// Like the race in mach_vm_remap_external_shared(), writes by other threads between
				// the copy above and this replacement are lost.
				//
				// Pages extracted into a named entry are inherited shared, not copied, across fork:
				// the child maps the same memfd.
				//
				// A range that is already a shared host mapping (a file, or a mapping of another
				// named entry) keeps its mapping, and the entry gets a snapshot of its contents.
				if (dtape_hooks->task_map_file(target_map->dtape_task->context, descriptor->memfd, map_size / (page_mask + 1), dtape_linux_protection(region_protection), map_start, 0, dtape_memory_flag_fixed | dtape_memory_flag_overwrite) != map_start) {
					kr = KERN_FAILURE;
					goto out;
				}
			}
		}
	}

	kr = mach_memory_entry_allocate(&user_entry, &user_handle);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	user_entry->dtape_descriptor = descriptor;
	descriptor = NULL; // the entry now owns the reference
	user_entry->size = map_size;
	user_entry->offset = entry_offset;
	user_entry->data_offset = offset_in_page;
	user_entry->protection = protections;
	user_entry->internal = (permission & MAP_MEM_NAMED_CREATE) != 0;

	*size = map_size - offset_in_page;
	*object_handle = user_handle;

out:
	if (staged) {
		munmap(staged, map_size);
	}
	if (descriptor) {
		dtape_map_shared_descriptor_release(descriptor);
	}
	return kr;
};

kern_return_t mach_memory_entry_access_tracking(ipc_port_t entry_port, int* access_tracking, uint32_t* access_tracking_reads, uint32_t* access_tracking_writes) {
	if (!is_named_entry_port(entry_port)) {
		return KERN_INVALID_ARGUMENT;
	}

	// access tracking is not available (as on release XNU kernels)
	return KERN_NOT_SUPPORTED;
};

kern_return_t mach_memory_entry_ownership(ipc_port_t entry_port, task_t owner, int ledger_tag, int ledger_flags) {
	if (ledger_flags & ~VM_LEDGER_FLAGS) {
		return KERN_INVALID_ARGUMENT;
	}
	if (ledger_tag <= 0 || ledger_tag > VM_LEDGER_TAG_MAX) {
		return KERN_INVALID_ARGUMENT;
	}
	if (!is_named_entry_port(entry_port)) {
		return KERN_INVALID_ARGUMENT;
	}

	// there are no memory ledgers; ownership has no observable effect
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t mach_memory_entry_purgable_control(ipc_port_t entry_port, vm_purgable_t control, int* state) {
	// XNU answers a port that is not a named entry with KERN_INVALID_ARGUMENT,
	// and so does every control (GET_STATE included) on a non-purgeable object;
	// neither kind of entry exists here
	return KERN_INVALID_ARGUMENT;
};

kern_return_t mach_memory_info(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp, mach_zone_info_array_t* infop, mach_msg_type_number_t* infoCntp, mach_memory_info_array_t* memoryInfop, mach_msg_type_number_t* memoryInfoCntp) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	// Clients reach this through MIG; failing the call, not the server, lets them fall back.
	dtape_stub("no memory entries");
	return KERN_NOT_SUPPORTED;
};

kern_return_t mach_memory_object_memory_entry_64(host_t host, boolean_t internal, vm_object_offset_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	// Clients reach this through MIG; failing the call, not the server, lets them fall back.
	dtape_stub("no memory entries");
	return KERN_NOT_SUPPORTED;
};

void pmap_require(pmap_t pmap) {
	dtape_stub_safe();
};

kern_return_t vm_allocate_cpm(host_priv_t host_priv, vm_map_t map, vm_address_t* addr, vm_size_t size, int flags) {
	dtape_stub_unsafe();
};

kern_return_t vm32_mapped_pages_info(vm_map_t map, page_address_array_t* pages, mach_msg_type_number_t* pages_count) {
	dtape_stub_unsafe();
};

kern_return_t vm32_region_info(vm_map_t map, vm32_offset_t address, vm_info_region_t* regionp, vm_info_object_array_t* objectsp, mach_msg_type_number_t* objectsCntp) {
	dtape_stub_unsafe();
};

kern_return_t vm32_region_info_64(vm_map_t map, vm32_offset_t address, vm_info_region_64_t* regionp, vm_info_object_array_t* objectsp, mach_msg_type_number_t* objectsCntp) {
	dtape_stub_unsafe();
};

memory_object_t convert_port_to_memory_object(mach_port_t port) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_behavior_set(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_behavior_t new_behavior) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_inherit(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_inherit_t new_inheritance) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_machine_attribute(vm_map_t map, mach_vm_address_t addr, mach_vm_size_t size, vm_machine_attribute_t attribute, vm_machine_attribute_val_t* value) {
	dtape_stub_unsafe();
};

// maps `page_count` pages in the task: anonymous memory if `descriptor` is NULL, otherwise its memfd (shared) from `page_offset`
static uintptr_t dtape_task_map_pages(vm_map_t map, dtape_map_shared_descriptor_t* descriptor, uint64_t page_count, int prot, uintptr_t address, uint64_t page_offset, dtape_memory_flags_t flags) {
	if (descriptor) {
		return dtape_hooks->task_map_file(map->dtape_task->context, descriptor->memfd, page_count, prot, address, page_offset, flags);
	} else {
		return dtape_hooks->task_allocate_pages(map->dtape_task->context, page_count, prot, address, flags);
	}
};

kern_return_t mach_vm_map_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t initial_size, mach_vm_offset_t mask, int flags, ipc_port_t port, vm_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance) {
	const uint64_t page_size = sysconf(_SC_PAGESIZE);
	const uint64_t page_mask = page_size - 1;
	bool mask_cur_protection = (cur_protection & VM_PROT_IS_MASK) != 0;
	bool mask_max_protection = (max_protection & VM_PROT_IS_MASK) != 0;
	dtape_map_shared_descriptor_t* descriptor = NULL;
	uint64_t object_offset = 0;
	kern_return_t kr = KERN_SUCCESS;

	cur_protection &= ~VM_PROT_IS_MASK;
	max_protection &= ~VM_PROT_IS_MASK;

	if (target_map == VM_MAP_NULL || address == NULL || (flags & ~VM_FLAGS_USER_MAP) ||
	    (cur_protection & ~VM_PROT_ALL) || (max_protection & ~VM_PROT_ALL) ||
	    inheritance > VM_INHERIT_LAST_VALID || initial_size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flags & VM_FLAGS_RETURN_4K_DATA_ADDR) {
		// only meaningful on 16K-page systems
		return KERN_NOT_SUPPORTED;
	}

	// The inheritance is not recorded: every mapping is inherited across fork the way Linux does it,
	// i.e. anonymous memory is copied and named-entry memory is shared.
	// VM_FLAGS_PURGABLE memory is never purged (nothing here can purge memory).

	if (IP_VALID(port)) {
		vm_named_entry_t entry;

		if (ip_kotype(port) != IKOT_NAMED_ENTRY) {
			// memory object (pager) ports are not supported
			return KERN_INVALID_OBJECT;
		}

		entry = (vm_named_entry_t)ip_get_kobject(port);

		if (copy) {
			// mapping a private copy of an entry's object is not supported; refuse instead of sharing
			return KERN_INVALID_ARGUMENT;
		}

		named_entry_lock(entry);
		if (!entry->dtape_descriptor) {
			kr = KERN_INVALID_OBJECT;
		} else {
			if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
				offset += entry->data_offset;
			}
			if (mask_max_protection) {
				max_protection &= entry->protection;
			}
			if (mask_cur_protection) {
				cur_protection &= entry->protection;
			}
			// XNU refuses rights the entry does not grant (e.g. writable mappings of a read-only entry)
			if ((entry->protection & max_protection) != max_protection ||
			    (entry->protection & cur_protection) != cur_protection) {
				kr = KERN_INVALID_RIGHT;
			} else if (offset + initial_size < offset || entry->size < offset + initial_size) {
				kr = KERN_INVALID_ARGUMENT;
			} else {
				descriptor = entry->dtape_descriptor;
				dtape_map_shared_descriptor_retain(descriptor);
				object_offset = entry->offset + offset;
			}
		}
		named_entry_unlock(entry);

		if (kr != KERN_SUCCESS) {
			return kr;
		}
	}

	uint64_t offset_in_page = object_offset & page_mask;
	uint64_t page_count = (offset_in_page + initial_size + page_mask) / page_size;
	uint64_t page_offset = object_offset / page_size;
	int prot = dtape_linux_protection(cur_protection);
	uintptr_t mapped = 0;

	if (!(flags & VM_FLAGS_ANYWHERE)) {
		dtape_memory_flags_t memflags = dtape_memory_flag_fixed;
		if (flags & VM_FLAGS_OVERWRITE) {
			memflags |= dtape_memory_flag_overwrite;
		}
		mapped = dtape_task_map_pages(target_map, descriptor, page_count, prot, *address & ~page_mask, page_offset, memflags);
		if (!mapped) {
			kr = KERN_NO_SPACE;
		}
	} else if ((mask | page_mask) == page_mask) {
		// *address is only a hint for where to start looking
		mapped = dtape_task_map_pages(target_map, descriptor, page_count, prot, *address & ~page_mask, page_offset, dtape_memory_flag_none);
		if (!mapped) {
			kr = KERN_NO_SPACE;
		}
	} else {
		// the address must be aligned to (mask + 1): reserve enough space to find an aligned
		// address in it, map there, and give back the rest of the reservation
		uint64_t alignment_pages = ((mask | page_mask) + 1) / page_size;
		uint64_t reserved_pages = page_count + alignment_pages - 1;
		uintptr_t reserved = dtape_hooks->task_allocate_pages(target_map->dtape_task->context, reserved_pages, PROT_NONE, *address & ~page_mask, dtape_memory_flag_none);
		if (!reserved) {
			kr = KERN_NO_SPACE;
		} else {
			uintptr_t aligned = (reserved + (mask | page_mask)) & ~(uintptr_t)(mask | page_mask);
			uintptr_t reserved_end = reserved + reserved_pages * page_size;
			uintptr_t mapped_end = aligned + page_count * page_size;

			mapped = dtape_task_map_pages(target_map, descriptor, page_count, prot, aligned, page_offset, dtape_memory_flag_fixed | dtape_memory_flag_overwrite);
			if (!mapped) {
				kr = KERN_NO_SPACE;
				dtape_hooks->task_free_pages(target_map->dtape_task->context, reserved, reserved_pages);
			} else {
				if (aligned > reserved) {
					dtape_hooks->task_free_pages(target_map->dtape_task->context, reserved, (aligned - reserved) / page_size);
				}
				if (reserved_end > mapped_end) {
					dtape_hooks->task_free_pages(target_map->dtape_task->context, mapped_end, (reserved_end - mapped_end) / page_size);
				}
			}
		}
	}

	// the task's mapping keeps the memfd open; the server does not need it any longer
	if (descriptor) {
		dtape_map_shared_descriptor_release(descriptor);
	}

	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*address = mapped;
	if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
		*address += offset_in_page;
	}
	return KERN_SUCCESS;
};

kern_return_t mach_vm_msync(vm_map_t map, mach_vm_offset_t address, mach_vm_size_t size, vm_sync_t sync_flags) {
	int linux_flags = 0;

	// TODO: give the Linux bits names/macros

	if (sync_flags & VM_SYNC_ASYNCHRONOUS) {
		linux_flags |= 1 << 0;
	}

	if (sync_flags & VM_SYNC_SYNCHRONOUS) {
		linux_flags |= 1 << 2;
	}

	if (sync_flags & VM_SYNC_INVALIDATE) {
		linux_flags |= 1 << 1;
	}

	if (!dtape_hooks->task_sync_memory(map->dtape_task->context, address, size, linux_flags)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
};

kern_return_t mach_vm_page_info(vm_map_t map, mach_vm_address_t address, vm_page_info_flavor_t flavor, vm_page_info_t info, mach_msg_type_number_t* count) {
	if (!count) {
		return KERN_INVALID_ARGUMENT;
	}

	// validate the request as XNU does, so unknown flavors keep their usual error
	switch (flavor) {
		case VM_PAGE_INFO_BASIC:
			// XNU also accepts one int less (the structure was once unpadded)
			if (*count != VM_PAGE_INFO_BASIC_COUNT && *count != VM_PAGE_INFO_BASIC_COUNT - 1) {
				return KERN_INVALID_ARGUMENT;
			}
			break;
		default:
			return KERN_INVALID_ARGUMENT;
	}

	// Page accounting is not implemented; let the caller handle unsupported queries.
	*count = 0;
	return KERN_NOT_SUPPORTED;
};

kern_return_t mach_vm_page_query(vm_map_t map, mach_vm_offset_t offset, int* disposition, int* ref_count) {
	return vm_map_page_query_internal(map, offset, disposition, ref_count);
};

kern_return_t mach_vm_page_range_query(vm_map_t map, mach_vm_offset_t address, mach_vm_size_t size, mach_vm_address_t dispositions_addr, mach_vm_size_t* dispositions_count) {
	// Page accounting is not implemented; let the caller handle unsupported queries.
	if (dispositions_count) *dispositions_count = 0;
	return KERN_NOT_SUPPORTED;
};

kern_return_t mach_vm_protect(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
	// we ignore `set_maximum`

	int prot = 0;

	uintptr_t end_memaddr = mach_vm_round_page(start + size);
	uintptr_t start_memaddr = mach_vm_trunc_page(start);
	size_t protect_size = end_memaddr - start_memaddr;

	if (new_protection & VM_PROT_READ) {
		prot |= PROT_READ;
	}
	if (new_protection & VM_PROT_WRITE) {
		prot |= PROT_WRITE;
	}
	if (new_protection & VM_PROT_EXECUTE) {
		prot |= PROT_EXEC;
	}

	if (!dtape_hooks->task_change_protection(map->dtape_task->context, start_memaddr, dtape_byte_count_to_page_count_round_up(protect_size), prot)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
};

kern_return_t mach_vm_purgable_control(vm_map_t map, mach_vm_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_read_list(vm_map_t map, mach_vm_read_entry_t data_list, natural_t count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_region(vm_map_t map, mach_vm_offset_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	switch (flavor) {
		case VM_REGION_BASIC_INFO:
		case VM_REGION_BASIC_INFO_64: {
			kern_return_t kr = KERN_FAILURE;
			dtape_memory_region_info_t region_info;

			uintptr_t addr_to_check = *address;

			if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
				addr_to_check = dtape_hooks->task_get_next_region(map->dtape_task->context, addr_to_check);
				if (addr_to_check == 0) {
					kr = KERN_NO_SPACE;
					goto region_info_out;
				}
				if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
					kr = KERN_FAILURE;
					goto region_info_out;
				}
			}

			*address = region_info.start_address;
			*size = region_info.page_count * sysconf(_SC_PAGESIZE);

			if (flavor == VM_REGION_BASIC_INFO_64) {
				vm_region_basic_info_64_t out = (vm_region_basic_info_64_t)info;

				if (*count < VM_REGION_BASIC_INFO_COUNT_64) {
					kr = KERN_INVALID_ARGUMENT;
					goto region_info_out;
				}
				*count = VM_REGION_BASIC_INFO_COUNT_64;

				out->protection = 0;

				if (region_info.protection & dtape_memory_protection_read)
					out->protection |= VM_PROT_READ;
				if (region_info.protection & dtape_memory_protection_write)
					out->protection |= VM_PROT_WRITE;
				// This is a special hack for LLDB. For processes started as suspended, with two RX segments.
				// However, in order to avoid failures, they are actually mapped as RWX and are to be changed to RX later by dyld.
				if (region_info.protection & dtape_memory_protection_execute)
					//out->protection |= VM_PROT_EXECUTE;
					out->protection = VM_PROT_EXECUTE | VM_PROT_READ;

				out->offset = region_info.map_offset;
				out->shared = region_info.shared;
				out->behavior = VM_BEHAVIOR_DEFAULT;
				out->user_wired_count = 0;
				out->inheritance = 0;
				out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
				out->reserved = FALSE;
			} else {
				vm_region_basic_info_t out = (vm_region_basic_info_t)info;

				if (*count < VM_REGION_BASIC_INFO_COUNT) {
					kr = KERN_INVALID_ARGUMENT;
					goto region_info_out;
				}
				*count = VM_REGION_BASIC_INFO_COUNT;

				out->protection = 0;

				if (region_info.protection & dtape_memory_protection_read)
					out->protection |= VM_PROT_READ;
				if (region_info.protection & dtape_memory_protection_write)
					out->protection |= VM_PROT_WRITE;
				// This is a special hack for LLDB. For processes started as suspended, with two RX segments.
				// However, in order to avoid failures, they are actually mapped as RWX and are to be changed to RX later by dyld.
				if (region_info.protection & dtape_memory_protection_execute)
					//out->protection |= VM_PROT_EXECUTE;
					out->protection = VM_PROT_EXECUTE | VM_PROT_READ;

				out->offset = region_info.map_offset;
				out->shared = region_info.shared;
				out->behavior = VM_BEHAVIOR_DEFAULT;
				out->user_wired_count = 0;
				out->inheritance = 0;
				out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
				out->reserved = FALSE;
			}

			kr = KERN_SUCCESS;

region_info_out:
			if (object_name)
				*object_name = IP_NULL;

			return kr;
		};
		default:
			// the flavor is guest-controlled: reject it as XNU does, never abort the server
			dtape_log_debug("%s: unsupported flavor %d", __FUNCTION__, flavor);
			if (object_name)
				*object_name = IP_NULL;
			return KERN_INVALID_ARGUMENT;
	}
};

kern_return_t mach_vm_region_recurse(vm_map_t map, mach_vm_address_t* address, mach_vm_size_t* size, uint32_t* depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
	kern_return_t kr = KERN_FAILURE;
	dtape_memory_region_info_t region_info;

	if (depth != NULL) {
		*depth = 0;
	}

	uintptr_t addr_to_check = *address;

	if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
		addr_to_check = dtape_hooks->task_get_next_region(map->dtape_task->context, addr_to_check);
		if (addr_to_check == 0) {
			kr = KERN_NO_SPACE;
			goto out;
		}
		if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
			kr = KERN_FAILURE;
			goto out;
		}
	}

	*address = region_info.start_address;
	*size = region_info.page_count * sysconf(_SC_PAGESIZE);

	if (*infoCnt == VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
		vm_region_submap_info_64_t out = (vm_region_submap_info_64_t)info;

		memset(out, 0, sizeof(*out));

		if (region_info.protection & dtape_memory_protection_read) {
			out->protection |= VM_PROT_READ;
		}
		if (region_info.protection & dtape_memory_protection_write) {
			out->protection |= VM_PROT_WRITE;
		}
		if (region_info.protection & dtape_memory_protection_execute) {
			out->protection |= VM_PROT_EXECUTE;
		}

		out->offset = region_info.map_offset;
		out->share_mode = region_info.shared ? SM_SHARED : SM_PRIVATE;
		out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	} else {
		// in the LKM, only VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 was implemented and everything was fine,
		// so it's fine to return KERN_INVALID_ARGUMENT here; log a message just in case, though.
		dtape_stub_safe("unsupported structure size");
		kr = KERN_INVALID_ARGUMENT;
	}

	kr = KERN_SUCCESS;

out:
	return kr;
};

static kern_return_t mach_vm_remap_external_shared(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_map, mach_vm_offset_t memory_address, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	kern_return_t kr = KERN_SUCCESS;
	int memfd = -1;
	void* mapped_addr = NULL;
	dtape_memory_region_info_t region_info;
	int prot = 0;
	vm_map_address_t target_addr = 0;
	vm_prot_t vm_prot = VM_PROT_NONE;
	dtape_map_shared_descriptor_t* descriptor = NULL;
	dtape_map_shared_entry_t* src_shared_entry = NULL;
	dtape_map_shared_entry_t* target_shared_entry = NULL;
	dtape_map_shared_entry_t* src_existing_entries[8];
	size_t src_existing_entry_count = 0;

	uintptr_t end_memaddr = mach_vm_round_page(memory_address + size);
	uintptr_t start_memaddr = mach_vm_trunc_page(memory_address);
	size_t map_size = end_memaddr - start_memaddr;

	if (!dtape_hooks->task_get_memory_region_info(src_map->dtape_task->context, memory_address, &region_info)) {
		kr = KERN_FAILURE;
		goto out;
	}

	if (region_info.protection & dtape_memory_protection_read) {
		prot |= PROT_READ;
		vm_prot |= VM_PROT_READ;
	}
	if (region_info.protection & dtape_memory_protection_write) {
		prot |= PROT_WRITE;
		vm_prot |= VM_PROT_WRITE;
	}
	if (region_info.protection & dtape_memory_protection_execute) {
		prot |= PROT_EXEC;
		vm_prot |= VM_PROT_EXECUTE;
	}

	dtape_mutex_lock(&src_map->shared_entry_lock);

	src_existing_entry_count = dtape_map_find_shared_entries_locked(src_map, start_memaddr, map_size, src_existing_entries, sizeof(src_existing_entries) / sizeof(*src_existing_entries));

	if (src_existing_entry_count == 1 && src_existing_entries[0]->address == start_memaddr && src_existing_entries[0]->size >= map_size) {
		// special case for what LLDB does with dyld info
		dtape_map_shared_descriptor_retain(src_existing_entries[0]->descriptor);
		descriptor = src_existing_entries[0]->descriptor;
		dtape_mutex_unlock(&src_map->shared_entry_lock);
		goto src_setup_done;
	} else if (src_existing_entry_count != 0) {
		// TODO: handle this case gracefully
		dtape_stub_unsafe("Cannot complexly remap existing shared regions yet");
	}

	dtape_mutex_unlock(&src_map->shared_entry_lock);

	memfd = memfd_create("darling-remapped", MFD_CLOEXEC);
	if (memfd < 0) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	if (ftruncate(memfd, map_size) < 0) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	mapped_addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
	if (mapped_addr == MAP_FAILED) {
		mapped_addr = NULL;
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	descriptor = dtape_map_shared_descriptor_create(memfd, map_size);
	if (!descriptor) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}
	memfd = -1; // the descriptor now owns the memfd

	// FIXME: there's a race here between us reading the memory from the source process into the memfd and
	//        when we actually replace the mapping in the source process with our shared version.
	//        in that short window, other threads in the source process may be modifying the region
	//        and any changes they make during that time will be lost when we replace it with our shared version.
	//
	//        even if we refactor this code to perform the memfd creation and setup within the source process,
	//        there would still be a race since we can't actually prevent other threads from accessing that memory.

	kr = copyinmap(src_map, start_memaddr, mapped_addr, map_size);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	if (dtape_hooks->task_map_file(src_map->dtape_task->context, descriptor->memfd, dtape_byte_count_to_page_count_round_up(map_size), prot, start_memaddr, 0, dtape_memory_flag_fixed | dtape_memory_flag_overwrite) != start_memaddr) {
		kr = KERN_FAILURE;
		goto out;
	}

	src_shared_entry = dtape_map_shared_entry_create(start_memaddr, map_size, 0, descriptor);
	if (!src_shared_entry) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dtape_map_insert_shared_entry(src_map, src_shared_entry);
	src_shared_entry = NULL; // the map now owns the shared entry

src_setup_done:
	target_addr = dtape_hooks->task_map_file(target_map->dtape_task->context, descriptor->memfd, dtape_byte_count_to_page_count_round_up(map_size), prot, 0, 0, dtape_memory_flag_none);
	if (!target_addr) {
		kr = KERN_FAILURE;
		goto out;
	}

	target_shared_entry = dtape_map_shared_entry_create(target_addr, map_size, 0, descriptor);
	if (!target_shared_entry) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dtape_map_insert_shared_entry(target_map, target_shared_entry);
	target_shared_entry = NULL; // the map now owns the shared entry

	*max_protection = VM_PROT_ALL;
	*cur_protection = vm_prot;
	*address = target_addr;

	if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
		*address += memory_address - start_memaddr;
	}

out:
	if (mapped_addr) {
		if (munmap(mapped_addr, map_size) < 0) {
			dtape_log_error("failed to unmap memfd");
		}
	}

	if (descriptor) {
		dtape_map_shared_descriptor_release(descriptor);
	}

	if (src_shared_entry) {
		dtape_map_shared_entry_destroy(src_shared_entry);
	}

	if (target_shared_entry) {
		dtape_map_shared_entry_destroy(target_shared_entry);
	}

	if (memfd >= 0) {
		close(memfd);
	}

	return kr;
};

kern_return_t mach_vm_remap_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_map, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	kern_return_t kr = KERN_SUCCESS;
	vm_map_copy_t mem_copy = NULL;
	vm_map_address_t addr = 0;
	bool dealloc = false;

	if (!copy) {
		return mach_vm_remap_external_shared(target_map, address, size, mask, flags, src_map, memory_address, cur_protection, max_protection, inheritance);
	}

	kr = vm_map_copyin(src_map, memory_address, size, FALSE, &mem_copy);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	dtape_memory_flags_t memflags = 0;
	if (!(flags & VM_FLAGS_ANYWHERE)) {
		memflags |= dtape_memory_flag_fixed;
	}
	if (flags & VM_FLAGS_OVERWRITE) {
		memflags |= dtape_memory_flag_overwrite;
	}

	int prot = PROT_READ | PROT_WRITE;

	// TODO: properly determine when to make memory executable by looking at the protection of the source region;
	//       for now, we just always make it executable for compatibility with libobjc's trampolines
	prot |= PROT_EXEC;

	addr = dtape_hooks->task_allocate_pages(target_map->dtape_task->context, dtape_byte_count_to_page_count_round_up(size), prot, (flags & VM_FLAGS_ANYWHERE) ? 0 : *address, memflags);
	if (!addr) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dealloc = true;

	kr = vm_map_copy_overwrite(target_map, addr, mem_copy, mem_copy->size, TRUE);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	dealloc = false;

	// a successful copy-out consumes the copy
	mem_copy = NULL;

	dtape_stub_safe("Determine correct protections for copied memory");
	*max_protection = VM_PROT_ALL;
	// LLDB doesn't like it when we tell it that memory is executable;
	// so don't tell it that it's executable, even if it is
	*cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	*address = addr;

out:
	if (mem_copy) {
		vm_map_copy_discard(mem_copy);
	}
	if (dealloc) {
		dtape_hooks->task_free_pages(target_map->dtape_task->context, addr, dtape_byte_count_to_page_count_round_up(size));
	}
	return kr;
};

// Code copied from xnu/osfmk/vm/vm_user.c
kern_return_t mach_vm_remap_new_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mach_port_t src_tport, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	vm_tag_t tag;
	vm_map_offset_t         map_addr;
	kern_return_t           kr;
	vm_map_t src_map;

	flags |= VM_FLAGS_RETURN_DATA_ADDR;
	VM_GET_FLAGS_ALIAS(flags, tag);

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_REMAP) {
		return KERN_INVALID_ARGUMENT;
	}

	if (target_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((*cur_protection & ~VM_PROT_ALL) ||
	    (*max_protection & ~VM_PROT_ALL) ||
	    (*cur_protection & *max_protection) != *cur_protection) {
		return KERN_INVALID_ARGUMENT;
	}
	if ((*max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
	    (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
		/*
		 * XXX FBDP TODO
		 * enforce target's "wx" policies
		 */
		return KERN_PROTECTION_FAILURE;
	}

	if (copy || *max_protection == VM_PROT_READ || *max_protection == VM_PROT_NONE) {
		src_map = convert_port_to_map_read(src_tport);
	} else {
		src_map = convert_port_to_map(src_tport);
	}

	if (src_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	map_addr = (vm_map_offset_t)*address;
	
	// I wasn't able to find an reimplementation of vm_map_remap in darlingserver,
	// so we will use mach_vm_remap_external for the time being.
	kr = mach_vm_remap_external(target_map,
	    &map_addr,
	    size,
	    mask,
	    flags,
	    src_map,
	    memory_address,
	    copy,
	    cur_protection,    /* IN/OUT */
	    max_protection,    /* IN/OUT */
	    inheritance);

	*address = map_addr;
	vm_map_deallocate(src_map);

	if (kr == KERN_SUCCESS) {
		ipc_port_release_send(src_tport);  /* consume on success */
	}
	return kr;
};

kern_return_t mach_vm_wire_external(host_priv_t host_priv, vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_prot_t access) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_force_gc(host_t host) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_get_btlog_records(host_priv_t host, mach_zone_name_t name, zone_btrecord_array_t* recsp, mach_msg_type_number_t* recsCntp) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t mach_zone_get_zlog_zones(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t mach_zone_info(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp, mach_zone_info_array_t* infop, mach_msg_type_number_t* infoCntp) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_info_for_largest_zone(host_priv_t host, mach_zone_name_t* namep, mach_zone_info_t* infop) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_info_for_zone(host_priv_t host, mach_zone_name_t name, mach_zone_info_t* infop) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_page_query_internal(vm_map_t target_map, vm_map_offset_t offset, int* disposition, int* ref_count) {
	// Page accounting is not implemented; let the caller handle unsupported queries.
	if (disposition) *disposition = 0;
	if (ref_count) *ref_count = 0;
	return KERN_NOT_SUPPORTED;
};

kern_return_t vm_map_purgable_control(vm_map_t map, vm_map_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region_recurse_64(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, natural_t* nesting_depth, vm_region_submap_info_64_t submap_info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_unwire(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, boolean_t user_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm_map_wire_kernel(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, vm_tag_t tag, boolean_t user_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm32__task_wire(vm_map_t map, boolean_t must_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm32__map_exec_lockdown(vm_map_t map) {
	dtape_stub_unsafe();
};

// <copied from="xnu://7195.141.2/osfmk/vm/vm_user.c">

/*
 *	mach_vm_allocate allocates "zero fill" memory in the specfied
 *	map.
 */
kern_return_t
mach_vm_allocate_external(
	vm_map_t                map,
	mach_vm_offset_t        *addr,
	mach_vm_size_t  size,
	int                     flags)
{
	vm_tag_t tag;

	VM_GET_FLAGS_ALIAS(flags, tag);
	return mach_vm_allocate_kernel(map, addr, size, flags, tag);
}

/*
 *	vm_wire -
 *	Specify that the range of the virtual address space
 *	of the target task must not cause page faults for
 *	the indicated accesses.
 *
 *	[ To unwire the pages, specify VM_PROT_NONE. ]
 */
kern_return_t
vm_wire(
	host_priv_t             host_priv,
	vm_map_t                map,
	vm_offset_t             start,
	vm_size_t               size,
	vm_prot_t               access)
{
	kern_return_t           rc;

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_HOST;
	}

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_TASK;
	}

	if ((access & ~VM_PROT_ALL) || (start + size < start)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (size == 0) {
		rc = KERN_SUCCESS;
	} else if (access != VM_PROT_NONE) {
		rc = vm_map_wire_kernel(map,
		    vm_map_trunc_page(start,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(start + size,
		    VM_MAP_PAGE_MASK(map)),
		    access, VM_KERN_MEMORY_OSFMK,
		    TRUE);
	} else {
		rc = vm_map_unwire(map,
		    vm_map_trunc_page(start,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(start + size,
		    VM_MAP_PAGE_MASK(map)),
		    TRUE);
	}
	return rc;
}

/*
 *	mach_vm_deallocate -
 *	deallocates the specified range of addresses in the
 *	specified address map.
 */
kern_return_t
mach_vm_deallocate(
	vm_map_t                map,
	mach_vm_offset_t        start,
	mach_vm_size_t  size)
{
	if ((map == VM_MAP_NULL) || (start + size < start)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (size == (mach_vm_offset_t) 0) {
		return KERN_SUCCESS;
	}

	return vm_map_remove(map,
	           vm_map_trunc_page(start,
	           VM_MAP_PAGE_MASK(map)),
	           vm_map_round_page(start + size,
	           VM_MAP_PAGE_MASK(map)),
	           VM_MAP_REMOVE_NO_FLAGS);
}

/*
 * mach_vm_copy -
 * Overwrite one range of the specified map with the contents of
 * another range within that same map (i.e. both address ranges
 * are "over there").
 */
kern_return_t
mach_vm_copy(
	vm_map_t                map,
	mach_vm_address_t       source_address,
	mach_vm_size_t  size,
	mach_vm_address_t       dest_address)
{
	vm_map_copy_t copy;
	kern_return_t kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_copyin(map, (vm_map_address_t)source_address,
	    (vm_map_size_t)size, FALSE, &copy);

	if (KERN_SUCCESS == kr) {
		if (copy) {
			assertf(copy->size == (vm_map_size_t) size, "Req size: 0x%llx, Copy size: 0x%llx\n", (uint64_t) size, (uint64_t) copy->size);
		}

		kr = vm_map_copy_overwrite(map,
		    (vm_map_address_t)dest_address,
		    copy, (vm_map_size_t) size, FALSE /* interruptible XXX */);

		if (KERN_SUCCESS != kr) {
			vm_map_copy_discard(copy);
		}
	}
	return kr;
}

/*
 * mach_vm_read -
 * Read/copy a range from one address space and return it to the caller.
 *
 * It is assumed that the address for the returned memory is selected by
 * the IPC implementation as part of receiving the reply to this call.
 * If IPC isn't used, the caller must deal with the vm_map_copy_t object
 * that gets returned.
 *
 * JMM - because of mach_msg_type_number_t, this call is limited to a
 * single 4GB region at this time.
 *
 */
kern_return_t
mach_vm_read(
	vm_map_t                map,
	mach_vm_address_t       addr,
	mach_vm_size_t  size,
	pointer_t               *data,
	mach_msg_type_number_t  *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   ipc_address;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((mach_msg_type_number_t) size != size) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map,
	    (vm_map_address_t)addr,
	    (vm_map_size_t)size,
	    FALSE,              /* src_destroy */
	    &ipc_address);

	if (KERN_SUCCESS == error) {
		*data = (pointer_t) ipc_address;
		*data_size = (mach_msg_type_number_t) size;
		assert(*data_size == size);
	}
	return error;
}

/*
 * mach_vm_read_overwrite -
 * Overwrite a range of the current map with data from the specified
 * map/address range.
 *
 * In making an assumption that the current thread is local, it is
 * no longer cluster-safe without a fully supportive local proxy
 * thread/task (but we don't support cluster's anymore so this is moot).
 */

kern_return_t
mach_vm_read_overwrite(
	vm_map_t                map,
	mach_vm_address_t       address,
	mach_vm_size_t  size,
	mach_vm_address_t       data,
	mach_vm_size_t  *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   copy;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map, (vm_map_address_t)address,
	    (vm_map_size_t)size, FALSE, &copy);

	if (KERN_SUCCESS == error) {
		if (copy) {
			assertf(copy->size == (vm_map_size_t) size, "Req size: 0x%llx, Copy size: 0x%llx\n", (uint64_t) size, (uint64_t) copy->size);
		}

		error = vm_map_copy_overwrite(current_thread()->map,
		    (vm_map_address_t)data,
		    copy, (vm_map_size_t) size, FALSE);
		if (KERN_SUCCESS == error) {
			*data_size = size;
			return error;
		}
		vm_map_copy_discard(copy);
	}
	return error;
}

/*
 * mach_vm_write -
 * Overwrite the specified address range with the data provided
 * (from the current map).
 */
kern_return_t
mach_vm_write(
	vm_map_t                        map,
	mach_vm_address_t               address,
	pointer_t                       data,
	mach_msg_type_number_t          size)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return vm_map_copy_overwrite(map, (vm_map_address_t)address,
	           (vm_map_copy_t) data, size, FALSE /* interruptible XXX */);
}

/*
 * mach_destroy_memory_entry:
 *
 * Drops a reference on a memory entry and destroys the memory entry if
 * there are no more references on it.
 * NOTE: This routine should not be called to destroy a memory entry from the
 * kernel, as it will not release the Mach port associated with the memory
 * entry.  The proper way to destroy a memory entry in the kernel is to
 * call mach_memort_entry_port_release() to release the kernel's send-right on
 * the memory entry's port.  When the last send right is released, the memory
 * entry will be destroyed via ipc_kobject_destroy().
 */
void
mach_destroy_memory_entry(
	ipc_port_t      port)
{
	vm_named_entry_t        named_entry;
#if MACH_ASSERT
	assert(ip_kotype(port) == IKOT_NAMED_ENTRY);
#endif /* MACH_ASSERT */
	named_entry = (vm_named_entry_t) ip_get_kobject(port);

	named_entry_lock(named_entry);
	named_entry->ref_count -= 1;

	if (named_entry->ref_count == 0) {
		if (named_entry->dtape_descriptor) {
			dtape_map_shared_descriptor_release(named_entry->dtape_descriptor);
			named_entry->dtape_descriptor = NULL;
		}
		if (named_entry->is_sub_map) {
			vm_map_deallocate(named_entry->backing.map);
		} else if (named_entry->is_copy) {
			vm_map_copy_discard(named_entry->backing.copy);
		} else if (named_entry->is_object) {
#ifndef __DARLING__
			assert(named_entry->backing.copy->cpy_hdr.nentries == 1);
#endif // __DARLING__
			vm_map_copy_discard(named_entry->backing.copy);
		} else {
			assert(named_entry->backing.copy == VM_MAP_COPY_NULL);
		}

		named_entry_unlock(named_entry);
		named_entry_lock_destroy(named_entry);

#if VM_NAMED_ENTRY_LIST
		lck_mtx_lock_spin(&vm_named_entry_list_lock_data);
		queue_remove(&vm_named_entry_list, named_entry,
		    vm_named_entry_t, named_entry_list);
		assert(vm_named_entry_count > 0);
		vm_named_entry_count--;
		lck_mtx_unlock(&vm_named_entry_list_lock_data);
#endif /* VM_NAMED_ENTRY_LIST */

		kfree(named_entry, sizeof(struct vm_named_entry));
	} else {
		named_entry_unlock(named_entry);
	}
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/vm/vm_map.c">

void
vm_map_read_deallocate(
	vm_map_read_t      map)
{
	vm_map_deallocate((vm_map_t)map);
}

/*
 *	Routine:	convert_port_entry_to_map
 *	Purpose:
 *		Convert from a port specifying an entry or a task
 *		to a map. Doesn't consume the port ref; produces a map ref,
 *		which may be null.  Unlike convert_port_to_map, the
 *		port may be task or a named entry backed.
 *	Conditions:
 *		Nothing locked.
 */


vm_map_t
convert_port_entry_to_map(
	ipc_port_t      port)
{
	vm_map_t map;
	vm_named_entry_t        named_entry;
	uint32_t        try_failed_count = 0;

	if (IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while (TRUE) {
			ip_lock(port);
			if (ip_active(port) && (ip_kotype(port)
			    == IKOT_NAMED_ENTRY)) {
				named_entry =
				    (vm_named_entry_t) ip_get_kobject(port);
				if (!(lck_mtx_try_lock(&(named_entry)->Lock))) {
					ip_unlock(port);

					try_failed_count++;
					mutex_pause(try_failed_count);
					continue;
				}
				named_entry->ref_count++;
				lck_mtx_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((named_entry->is_sub_map) &&
				    (named_entry->protection
				    & VM_PROT_WRITE)) {
					map = named_entry->backing.map;
#ifndef __DARLING__
					if (map->pmap != PMAP_NULL) {
						if (map->pmap == kernel_pmap) {
							panic("userspace has access "
							    "to a kernel map %p", map);
						}
						pmap_require(map->pmap);
					}
#endif // __DARLING__
				} else {
					mach_destroy_memory_entry(port);
					return VM_MAP_NULL;
				}
				vm_map_reference(map);
				mach_destroy_memory_entry(port);
				break;
			} else {
				return VM_MAP_NULL;
			}
		}
	} else {
		map = convert_port_to_map(port);
	}

	return map;
}

// </copied>
