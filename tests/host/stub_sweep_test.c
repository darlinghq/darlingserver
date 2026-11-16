// Guest-reachable Mach routines that used to be dtape_stub_unsafe() (see tests/run-stub-sweep.sh): each is called with
// arguments a guest could send and must return XNU's answer instead of aborting the server. Built with darlingserver's
// kernel flags, so no libc headers: printf is declared here and __builtin_setjmp/__builtin_longjmp catch an abort.
#include <kern/host.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/restartable.h>
#include <mach/mach_types.h>
#include <mach/vm_behavior.h>
#include <mach/vm_inherit.h>
#include <mach/vm_purgable.h>
#include <mach/vm_attributes.h>
#include <mach/task_policy.h>
#include <mach/policy.h>
#include <mach/thread_status.h>
#include <mach_debug/mach_debug.h>

int printf(const char*, ...);
void* calloc(unsigned long, unsigned long);

static void* abort_jmp[5];
static const char* aborted_in;
static int fails, aborts;

// the real one (duct-tape/src/log.c) logs; for safety -1 (dtape_stub_unsafe) the caller then hits
// __builtin_unreachable(): the server is gone
void dtape_stub_log(const char* function_name, int safety, const char* subsection) {
	if (safety < 0) {
		aborted_in = function_name;
		__builtin_longjmp(abort_jmp, 1);
	}
}

static struct thread* the_thread;
thread_t current_thread(void) { return the_thread; }
static int task_deallocs;
void task_deallocate(task_t task) { task_deallocs++; }

#define CALL(expr, expected, what) do { \
	if (__builtin_setjmp(abort_jmp) == 0) { \
		kern_return_t kr_ = (expr); \
		int ok_ = kr_ == (expected); \
		printf("%s %s: %d (want %d)\n", ok_ ? "PASS" : "FAIL", what, kr_, (int)(expected)); \
		if (!ok_) fails++; \
	} else { \
		printf("FAIL %s: ABORT (dtape_stub_unsafe in %s: darlingserver would die)\n", what, aborted_in); \
		fails++; aborts++; \
	} \
} while (0)
#define CHECK(c, what) do { int ok_ = (c); printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)
#define VOIDCALL(stmt, what) do { \
	if (__builtin_setjmp(abort_jmp) == 0) { stmt; printf("PASS %s: returned\n", what); } \
	else { printf("FAIL %s: ABORT (dtape_stub_unsafe in %s)\n", what, aborted_in); fails++; aborts++; } \
} while (0)

// MIG routines without a prototype in the kernel headers here
kern_return_t mach_vm_page_info(vm_map_t, mach_vm_address_t, vm_page_info_flavor_t, vm_page_info_t, mach_msg_type_number_t*);
kern_return_t vm_map_page_query_internal(vm_map_t, vm_map_offset_t, int*, int*);
kern_return_t vm_map_purgable_control(vm_map_t, vm_map_offset_t, vm_purgable_t, int*);
kern_return_t mach_vm_behavior_set(vm_map_t, mach_vm_offset_t, mach_vm_size_t, vm_behavior_t);
kern_return_t mach_vm_inherit(vm_map_t, mach_vm_offset_t, mach_vm_size_t, vm_inherit_t);
kern_return_t mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t*);
kern_return_t mach_vm_wire_external(host_priv_t, vm_map_t, mach_vm_offset_t, mach_vm_size_t, vm_prot_t);
kern_return_t mach_vm_read_list(vm_map_t, mach_vm_read_entry_t, natural_t);
kern_return_t mach_zone_info(host_priv_t, mach_zone_name_array_t*, mach_msg_type_number_t*, mach_zone_info_array_t*, mach_msg_type_number_t*);
kern_return_t mach_zone_force_gc(host_t);
kern_return_t mach_memory_info(host_priv_t, mach_zone_name_array_t*, mach_msg_type_number_t*, mach_zone_info_array_t*, mach_msg_type_number_t*, mach_memory_info_array_t*, mach_msg_type_number_t*);
kern_return_t mach_memory_object_memory_entry_64(host_t, boolean_t, vm_object_offset_t, vm_prot_t, memory_object_t, ipc_port_t*);
memory_object_t convert_port_to_memory_object(mach_port_t);
kern_return_t vm_allocate_cpm(host_priv_t, vm_map_t, vm_address_t*, vm_size_t, int);
kern_return_t vm32__map_exec_lockdown(vm_map_t);
kern_return_t host_get_boot_info(host_priv_t, kernel_boot_info_t);
kern_return_t host_reboot(host_priv_t, int);
kern_return_t host_virtual_physical_table_info(host_t, hash_info_bucket_array_t*, mach_msg_type_number_t*);
kern_return_t host_lockgroup_info(host_t, lockgroup_info_array_t*, mach_msg_type_number_t*);
kern_return_t processor_set_tasks(processor_set_t, task_array_t*, mach_msg_type_number_t*);
kern_return_t processor_set_threads(processor_set_t, thread_array_t*, mach_msg_type_number_t*);
kern_return_t processor_set_stack_usage(processor_set_t, unsigned int*, vm_size_t*, vm_size_t*, vm_size_t*, vm_offset_t*);
kern_return_t task_get_state(task_t, int, thread_state_t, mach_msg_type_number_t*);
kern_return_t task_set_state(task_t, int, thread_state_t, mach_msg_type_number_t);
kern_return_t task_purgable_info(task_t, task_purgable_info_t*);
kern_return_t task_generate_corpse(task_t, ipc_port_t*);
kern_return_t task_map_corpse_info_64(task_t, task_t, mach_vm_address_t*, mach_vm_size_t*);
kern_return_t task_dyld_process_info_notify_register(task_t, ipc_port_t);
kern_return_t task_register_dyld_image_infos(task_t, dyld_kernel_image_info_array_t, mach_msg_type_number_t);
kern_return_t thread_set_policy(thread_t, processor_set_t, policy_t, policy_base_t, mach_msg_type_number_t, policy_limit_t, mach_msg_type_number_t);
kern_return_t thread_create_running_from_user(task_t, int, thread_state_t, mach_msg_type_number_t, thread_t*);
kern_return_t act_get_state_to_user(thread_t, int, thread_state_t, mach_msg_type_number_t*);
ipc_port_t convert_suid_cred_to_port(suid_cred_t);

int main(void) {
	struct task* task = calloc(1, sizeof(struct task));
	struct thread* thread = calloc(1, sizeof(struct thread));
	struct thread* other = calloc(1, sizeof(struct thread));
	thread->task = task;
	the_thread = thread;
	host_t host = (host_t)calloc(1, 64);
	vm_map_t map = (vm_map_t)calloc(1, 4096);
	integer_t info[128]; // HOST_VM_PURGABLE_COUNT is 68
	mach_msg_type_number_t count;

	// host.c
	count = HOST_SCHED_INFO_COUNT;
	CALL(host_info(host, HOST_SCHED_INFO, info, &count), KERN_SUCCESS, "host_info(HOST_SCHED_INFO)");
	CHECK(count == HOST_SCHED_INFO_COUNT && info[0] == 10 && info[1] == 10, "HOST_SCHED_INFO: 10 ms quantum");
	count = HOST_RESOURCE_SIZES_COUNT;
	CALL(host_info(host, HOST_RESOURCE_SIZES, info, &count), KERN_INVALID_ARGUMENT, "host_info(HOST_RESOURCE_SIZES)");
	count = HOST_CAN_HAS_DEBUGGER_COUNT;
	CALL(host_info(host, HOST_CAN_HAS_DEBUGGER, info, &count), KERN_SUCCESS, "host_info(HOST_CAN_HAS_DEBUGGER)");
	count = HOST_VM_PURGABLE_COUNT;
	CALL(host_info(host, HOST_VM_PURGABLE, info, &count), KERN_SUCCESS, "host_info(HOST_VM_PURGABLE)");
	count = 1;
	CALL(host_info(host, HOST_VM_PURGABLE, info, &count), KERN_FAILURE, "host_info(HOST_VM_PURGABLE) short count");
	count = HOST_LOAD_INFO_COUNT;
	CALL(host_statistics(host, HOST_LOAD_INFO, info, &count), KERN_SUCCESS, "host_statistics(HOST_LOAD_INFO)");
	count = 64;
	CALL(host_statistics(host, 1234, info, &count), KERN_INVALID_ARGUMENT, "host_statistics(unknown flavor)");
	char boot[KERNEL_BOOT_INFO_MAX];
	CALL(host_get_boot_info(host, boot), KERN_SUCCESS, "host_get_boot_info");
	CALL(host_reboot(host, 0), KERN_NOT_SUPPORTED, "host_reboot");
	CALL(host_virtual_physical_table_info(host, 0, &count), KERN_FAILURE, "host_virtual_physical_table_info");
	CALL(host_lockgroup_info(host, 0, &count), KERN_NOT_SUPPORTED, "host_lockgroup_info");

	// memory.c
	struct { int disposition, ref_count; uint64_t object_id, offset; int depth, pad; } page;
	CALL(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&page, 0), KERN_INVALID_ARGUMENT, "mach_vm_page_info(NULL count)");
	count = VM_PAGE_INFO_BASIC_COUNT;
	CALL(mach_vm_page_info(map, 0x2000, 2, (vm_page_info_t)&page, &count), KERN_INVALID_ARGUMENT, "mach_vm_page_info(unknown flavor)");
	count = VM_PAGE_INFO_BASIC_COUNT - 2;
	CALL(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&page, &count), KERN_INVALID_ARGUMENT, "mach_vm_page_info(bad count)");
	count = VM_PAGE_INFO_BASIC_COUNT;
	CALL(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&page, &count), KERN_SUCCESS, "mach_vm_page_info(BASIC)");
	CHECK(page.disposition == VM_PAGE_QUERY_PAGE_PRESENT && page.ref_count == 1, "mach_vm_page_info: present, as mach_vm_page_query");
	int disposition = -1, ref_count = -1;
	CALL(vm_map_page_query_internal(map, 0x2000, &disposition, &ref_count), KERN_SUCCESS, "vm_map_page_query_internal (vm32 map_page_query)");
	int state = 0;
	CALL(vm_map_purgable_control(map, 0x2000, VM_PURGABLE_GET_STATE, &state), KERN_SUCCESS, "vm_map_purgable_control (vm32 purgable_control)");
	CALL(mach_vm_behavior_set(map, 0x2000, 0x1000, VM_BEHAVIOR_DONTNEED), KERN_SUCCESS, "mach_vm_behavior_set(DONTNEED)");
	CALL(mach_vm_behavior_set(map, 0x2000, 0x1000, 99), KERN_INVALID_ARGUMENT, "mach_vm_behavior_set(unknown)");
	CALL(mach_vm_inherit(map, 0x2000, 0x1000, VM_INHERIT_NONE), KERN_SUCCESS, "mach_vm_inherit(NONE)");
	CALL(mach_vm_inherit(map, 0x2000, 0x1000, 7), KERN_INVALID_ARGUMENT, "mach_vm_inherit(invalid)");
	vm_machine_attribute_val_t val = MATTR_VAL_CACHE_FLUSH;
	CALL(mach_vm_machine_attribute(map, 0x2000, 0x1000, MATTR_CACHE, &val), KERN_SUCCESS, "mach_vm_machine_attribute(MATTR_CACHE)");
	CALL(mach_vm_wire_external(host, map, 0x2000, 0x1000, VM_PROT_READ), KERN_SUCCESS, "mach_vm_wire_external");
	CALL(mach_vm_wire_external(HOST_PRIV_NULL, map, 0x2000, 0x1000, VM_PROT_READ), KERN_INVALID_HOST, "mach_vm_wire_external(no host_priv)");
	CALL(mach_vm_read_list(map, 0, VM_MAP_ENTRY_MAX + 1), KERN_INVALID_ARGUMENT, "mach_vm_read_list(too many entries)");
	CALL(mach_zone_info(host, 0, &count, 0, &count), KERN_FAILURE, "mach_zone_info");
	CALL(mach_zone_force_gc(host), KERN_SUCCESS, "mach_zone_force_gc");
	CALL(mach_memory_info(host, 0, &count, 0, &count, 0, &count), KERN_FAILURE, "mach_memory_info");
	ipc_port_t port = IP_NULL;
	memory_object_t pager = MEMORY_OBJECT_NULL;
	VOIDCALL(pager = convert_port_to_memory_object(MACH_PORT_NULL), "convert_port_to_memory_object");
	CHECK(pager == MEMORY_OBJECT_NULL, "convert_port_to_memory_object: no pagers");
	CALL(mach_memory_object_memory_entry_64(host, TRUE, 0x1000, VM_PROT_DEFAULT, MEMORY_OBJECT_NULL, &port), KERN_NOT_SUPPORTED, "mach_memory_object_memory_entry_64");
	vm_address_t addr = 0;
	CALL(vm_allocate_cpm(host, map, &addr, 0x1000, 0), KERN_FAILURE, "vm_allocate_cpm");
	CALL(vm32__map_exec_lockdown(map), KERN_SUCCESS, "vm32__map_exec_lockdown");

	// processor.c
	processor_t cpu = (processor_t)calloc(1, sizeof(struct processor));
	processor_set_t pset = PROCESSOR_SET_NULL;
	CALL(processor_control(cpu, info, 1), KERN_FAILURE, "processor_control");
	CALL(processor_exit_from_user(cpu), KERN_NOT_SUPPORTED, "processor_exit_from_user");
	CALL(processor_start_from_user(cpu), KERN_NOT_SUPPORTED, "processor_start_from_user");
	CALL(processor_get_assignment(cpu, &pset), KERN_SUCCESS, "processor_get_assignment");
	CHECK(pset == &pset0, "processor_get_assignment: pset0");
	CALL(processor_set_create(host, &pset, &pset), KERN_FAILURE, "processor_set_create");
	CALL(processor_set_destroy(&pset0), KERN_FAILURE, "processor_set_destroy");
	CALL(processor_set_max_priority(&pset0, 31, FALSE), KERN_INVALID_ARGUMENT, "processor_set_max_priority");
	CALL(processor_set_policy_enable(&pset0, POLICY_RR), KERN_INVALID_ARGUMENT, "processor_set_policy_enable");
	CALL(processor_set_policy_disable(&pset0, POLICY_RR, FALSE), KERN_INVALID_ARGUMENT, "processor_set_policy_disable");
	CALL(processor_set_policy_control(&pset0, 0, info, 0, FALSE), KERN_INVALID_ARGUMENT, "processor_set_policy_control");
	unsigned int total; vm_size_t sz; vm_offset_t off;
	CALL(processor_set_stack_usage(&pset0, &total, &sz, &sz, &sz, &off), KERN_NOT_SUPPORTED, "processor_set_stack_usage");
	CALL(processor_set_tasks(&pset0, 0, &count), KERN_NOT_SUPPORTED, "processor_set_tasks");
	CALL(processor_set_threads(&pset0, 0, &count), KERN_FAILURE, "processor_set_threads");

	// task.c
	natural_t ds[64];
	count = x86_DEBUG_STATE64_COUNT;
	CALL(task_get_state(task, x86_DEBUG_STATE64, ds, &count), KERN_SUCCESS, "task_get_state(x86_DEBUG_STATE64)");
	CHECK(count == x86_DEBUG_STATE64_COUNT && ds[0] == 0, "task_get_state: no task-wide breakpoints");
	count = 64;
	CALL(task_get_state(task, x86_THREAD_STATE64, ds, &count), KERN_INVALID_ARGUMENT, "task_get_state(thread state flavor)");
	for (int i = 0; i < 64; i++) ds[i] = 0;
	CALL(task_set_state(task, x86_DEBUG_STATE64, ds, x86_DEBUG_STATE64_COUNT), KERN_SUCCESS, "task_set_state(clear debug state)");
	ds[0] = 0x1000;
	CALL(task_set_state(task, x86_DEBUG_STATE64, ds, x86_DEBUG_STATE64_COUNT), KERN_NOT_SUPPORTED, "task_set_state(breakpoint)");
	boolean_t def = FALSE;
	count = TASK_CATEGORY_POLICY_COUNT;
	CALL(task_policy_get(task, TASK_CATEGORY_POLICY, info, &count, &def), KERN_SUCCESS, "task_policy_get(CATEGORY)");
	CHECK(info[0] == TASK_UNSPECIFIED, "task_policy_get: role unspecified");
	count = TASK_SUPPRESSION_POLICY_COUNT;
	CALL(task_policy_get(task, TASK_SUPPRESSION_POLICY, info, &count, &def), KERN_SUCCESS, "task_policy_get(SUPPRESSION)");
	count = 64;
	CALL(task_policy_get(task, 99, info, &count, &def), KERN_INVALID_ARGUMENT, "task_policy_get(unknown)");
	task_purgable_info_t purg;
	CALL(task_purgable_info(task, &purg), KERN_SUCCESS, "task_purgable_info");
	CALL(task_set_info(task, TASK_BASIC_INFO_64, info, 0), KERN_INVALID_ARGUMENT, "task_set_info");
	CALL(task_terminate(task), KERN_FAILURE, "task_terminate (a BSD task)");
	CALL(task_get_assignment(task, &pset), KERN_SUCCESS, "task_get_assignment");
	CALL(task_generate_corpse(task, &port), KERN_NOT_SUPPORTED, "task_generate_corpse");
	mach_vm_address_t kcd; mach_vm_size_t kcdsz;
	CALL(task_map_corpse_info_64(task, task, &kcd, &kcdsz), KERN_INVALID_ARGUMENT, "task_map_corpse_info_64");
	CALL(task_dyld_process_info_notify_register(task, IP_NULL), KERN_INVALID_RIGHT, "task_dyld_process_info_notify_register(no right)");
	CALL(task_register_dyld_image_infos(task, 0, 0), KERN_INVALID_ADDRESS, "task_register_dyld_image_infos(no data)");
	task_restartable_range_t range = { .location = 0x10000, .length = 0x40, .recovery_offs = 0x20, .flags = 0 };
	CALL(task_restartable_ranges_register(task, &range, 1), KERN_SUCCESS, "task_restartable_ranges_register");
	range.flags = 1;
	CALL(task_restartable_ranges_register(task, &range, 1), KERN_INVALID_ARGUMENT, "task_restartable_ranges_register(flags)");
	CALL(task_restartable_ranges_synchronize(task), KERN_SUCCESS, "task_restartable_ranges_synchronize");
	task_deallocs = 0;
	VOIDCALL(task_name_deallocate((task_name_t)task), "task_name_deallocate (mach_task_is_self)");
	VOIDCALL(task_suspension_token_deallocate((task_suspension_token_t)task), "task_suspension_token_deallocate (task_resume2)");
	VOIDCALL(task_policy_get_deallocate((task_policy_get_t)task), "task_policy_get_deallocate");
	CHECK(task_deallocs == 3, "the deallocators drop their task reference");

	// thread.c
	natural_t in[4] = { 1, 2, 3, 4 }, out[8];
	count = 8;
	CALL(thread_convert_thread_state(other, THREAD_CONVERT_THREAD_STATE_FROM_SELF, x86_THREAD_STATE64, in, 4, out, &count), KERN_SUCCESS, "thread_convert_thread_state");
	CHECK(count == 4 && out[3] == 4, "thread_convert_thread_state: copied");
	count = 2;
	CALL(thread_convert_thread_state(other, THREAD_CONVERT_THREAD_STATE_FROM_SELF, x86_THREAD_STATE64, in, 4, out, &count), KERN_INSUFFICIENT_BUFFER_SIZE, "thread_convert_thread_state(short)");
	struct policy_timeshare_base base = { .base_priority = 31 };
	struct policy_timeshare_limit limit = { .max_priority = 63 };
	CALL(thread_set_policy(other, &pset0, POLICY_TIMESHARE, (policy_base_t)&base, POLICY_TIMESHARE_BASE_COUNT, (policy_limit_t)&limit, POLICY_TIMESHARE_LIMIT_COUNT), KERN_SUCCESS, "thread_set_policy(TIMESHARE)");
	CALL(thread_set_policy(other, &pset0, 77, (policy_base_t)&base, 1, (policy_limit_t)&limit, 1), KERN_INVALID_ARGUMENT, "thread_set_policy(bad policy)");
	thread_t made = THREAD_NULL;
	CALL(thread_create_from_user(task, &made), KERN_NOT_SUPPORTED, "thread_create_from_user");
	CALL(thread_create_running_from_user(task, x86_THREAD_STATE64, in, 4, &made), KERN_NOT_SUPPORTED, "thread_create_running_from_user");
	count = 4;
	CALL(act_get_state_to_user(thread, x86_THREAD_STATE64, out, &count), KERN_INVALID_ARGUMENT, "act_get_state_to_user(self)");
	CALL(thread_wire(host, other, TRUE), KERN_INVALID_ARGUMENT, "thread_wire(other thread)");
	CALL(thread_set_mach_voucher(other, IPC_VOUCHER_NULL), KERN_INVALID_ARGUMENT, "thread_set_mach_voucher(other thread)");
	CALL(thread_abort(THREAD_NULL), KERN_INVALID_ARGUMENT, "thread_abort(NULL)");

	// stubs.c
	VOIDCALL(port = convert_suid_cred_to_port(0), "convert_suid_cred_to_port");

	printf("%s (%d failures, %d server aborts)\n", fails ? "FAILED" : "OK", fails, aborts);
	return fails != 0;
}
