#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/hooks.h>

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

#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE 0x02

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_FAILED ((void*)-1)

#define _SC_PAGESIZE 30

void dtape_memory_init(void) {

};

vm_map_t dtape_vm_map_create(struct dtape_task* task) {
	vm_map_t map = malloc(sizeof(struct _vm_map));
	if (!map) {
		return map;
	}

	os_ref_init(&map->map_refcnt, NULL);

	map->max_offset = MACH_VM_MAX_ADDRESS;
	map->dtape_page_shift = __builtin_ctzl(sysconf(_SC_PAGESIZE));

	map->dtape_task = task;

	return map;
};

void dtape_vm_map_destroy(vm_map_t map) {
	if (os_ref_release(&map->map_refcnt) != 0) {
		panic("VM map still in-use at destruction");
	}

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

void vm_map_copy_discard(vm_map_copy_t copy) {
	dtape_stub();
};

void (kheap_free)(kalloc_heap_t kheap, void* addr, vm_size_t size) {
	free(addr);
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
	void* memory = aligned_alloc(power_of_2, size);
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
		memmove(fromdata, (void*)toaddr, length);
		return KERN_SUCCESS;
	} else {
		return dtape_hooks->task_write_memory(map->dtape_task->context, toaddr, fromdata, length) ? KERN_SUCCESS : KERN_FAILURE;
	}
};

kern_return_t copyinmap(vm_map_t map, vm_map_offset_t fromaddr, void* todata, vm_size_t length) {
	if (map == kernel_map) {
		memmove((void*)fromaddr, todata, length);
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

vm_map_t convert_port_entry_to_map(ipc_port_t port) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_behavior_set(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_behavior_t new_behavior) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_copy(vm_map_t map, mach_vm_address_t source_address, mach_vm_size_t size, mach_vm_address_t dest_address) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_deallocate(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size) {
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

kern_return_t mach_vm_msync(vm_map_t map, mach_vm_address_t address, mach_vm_size_t size, vm_sync_t sync_flags) {
	dtape_stub_unsafe();
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
	dtape_stub_unsafe();
};

kern_return_t mach_vm_purgable_control(vm_map_t map, mach_vm_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_read(vm_map_t map, mach_vm_address_t addr, mach_vm_size_t size, pointer_t* data, mach_msg_type_number_t* data_size) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_read_list(vm_map_t map, mach_vm_read_entry_t data_list, natural_t count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_read_overwrite(vm_map_t map, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t* data_size) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_region(vm_map_t map, mach_vm_offset_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_region_recurse(vm_map_t map, mach_vm_address_t* address, mach_vm_size_t* size, uint32_t* depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_remap_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_map, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_remap_new_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mach_port_t src_tport, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_wire_external(host_priv_t host_priv, vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_prot_t access) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_write(vm_map_t map, mach_vm_address_t address, pointer_t data, mach_msg_type_number_t size) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_allocate_kernel(vm_map_t map, mach_vm_offset_t* addr, mach_vm_size_t size, int flags, vm_tag_t tag) {
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

boolean_t vm_kernel_map_is_kernel(vm_map_t map) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_copyin_common(vm_map_t src_map, vm_map_address_t src_addr, vm_map_size_t len, boolean_t src_destroy, boolean_t src_volatile, vm_map_copy_t* copy_result, boolean_t use_maxprot) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_copyout_size(vm_map_t dst_map, vm_map_address_t* dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_copy_overwrite(vm_map_t dst_map, vm_map_offset_t dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size, boolean_t interruptible) {
	dtape_stub_unsafe();
};

boolean_t vm_map_copy_validate_size(vm_map_t dst_map, vm_map_copy_t copy, vm_map_size_t* size) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_page_query_internal(vm_map_t target_map, vm_map_offset_t offset, int* disposition, int* ref_count) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_purgable_control(vm_map_t map, vm_map_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

void vm_map_read_deallocate(vm_map_read_t map) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region_recurse_64(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, natural_t* nesting_depth, vm_region_submap_info_64_t submap_info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_unwire(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, boolean_t user_wire) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_wire_kernel(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, vm_tag_t tag, boolean_t user_wire) {
	dtape_stub_unsafe();
};

kern_return_t vm32__task_wire(vm_map_t map, boolean_t must_wire) {
	dtape_stub_unsafe();
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

// </copied>
 