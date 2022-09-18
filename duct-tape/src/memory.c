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
		if (entry->address + entry->size < address || entry->address > address + size) {
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
	return (copyinmap(current_map(), user_addr, kernel_addr, nbytes) == KERN_SUCCESS) ? 0 : 1;
};

int (copyout)(const void* kernel_addr, user_addr_t user_addr, vm_size_t nbytes) {
	// it doesn't actually modify kernel_addr
	return (copyoutmap(current_map(), (void*)kernel_addr, user_addr, nbytes) == KERN_SUCCESS) ? 0 : 1;
};

int copyinmsg(const user_addr_t user_addr, char* kernel_addr, mach_msg_size_t nbytes) {
	return (copyin)(user_addr, kernel_addr, nbytes);
};

int copyoutmsg(const char* kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes) {
	return (copyout)(kernel_addr, user_addr, nbytes);
};

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

kern_return_t _mach_make_memory_entry(vm_map_t target_map, memory_object_size_t* size, memory_object_offset_t offset, vm_prot_t permission, ipc_port_t* object_handle, ipc_port_t parent_entry) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_entry_access_tracking(ipc_port_t entry_port, int* access_tracking, uint32_t* access_tracking_reads, uint32_t* access_tracking_writes) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_entry_ownership(ipc_port_t entry_port, task_t owner, int ledger_tag, int ledger_flags) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_entry_purgable_control(ipc_port_t entry_port, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_info(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp, mach_zone_info_array_t* infop, mach_msg_type_number_t* infoCntp, mach_memory_info_array_t* memoryInfop, mach_msg_type_number_t* memoryInfoCntp) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_object_memory_entry_64(host_t host, boolean_t internal, vm_object_offset_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	dtape_stub_unsafe();
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

kern_return_t mach_vm_map_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t initial_size, mach_vm_offset_t mask, int flags, ipc_port_t port, vm_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance) {
	dtape_stub_unsafe();
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
	dtape_stub_unsafe();
};

kern_return_t mach_vm_page_query(vm_map_t map, mach_vm_offset_t offset, int* disposition, int* ref_count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_page_range_query(vm_map_t map, mach_vm_offset_t address, mach_vm_size_t size, mach_vm_address_t dispositions_addr, mach_vm_size_t* dispositions_count) {
	dtape_stub_unsafe();
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
			dtape_stub_unsafe("Unimplemented flavor");
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
	dtape_stub_unsafe();
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
