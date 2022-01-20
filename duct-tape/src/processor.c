#include <darlingserver/duct-tape/stubs.h>

#include <kern/processor.h>
#include <kern/kalloc.h>

processor_t processor_array[MAX_SCHED_CPUS] = {0};
struct processor_set pset0;
uint32_t processor_avail_count;
uint32_t processor_avail_count_user;
uint32_t primary_processor_avail_count;
uint32_t primary_processor_avail_count_user;
unsigned int processor_count;
simple_lock_data_t processor_list_lock;
processor_t master_processor;

void dtape_processor_init(void) {
	simple_lock_init(&processor_list_lock, 0);

	master_processor = kalloc(sizeof(*master_processor));
	memset(master_processor, 0, sizeof(*master_processor));
};

kern_return_t processor_assign(processor_t processor, processor_set_t new_pset, boolean_t wait) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t processor_control(processor_t processor, processor_info_t info, mach_msg_type_number_t count) {
	dtape_stub_unsafe();
};

kern_return_t processor_exit_from_user(processor_t processor) {
	dtape_stub_unsafe();
};

kern_return_t processor_get_assignment(processor_t processor, processor_set_t* pset) {
	dtape_stub_unsafe();
};

kern_return_t processor_info(processor_t processor, processor_flavor_t flavor, host_t* host, processor_info_t info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_info_count(processor_flavor_t flavor, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_create(host_t host, processor_set_t* new_set, processor_set_t* new_name) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_destroy(processor_set_t pset) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_info(processor_set_t pset, int flavor, host_t* host, processor_set_info_t info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_max_priority(processor_set_t pset, int max_priority, boolean_t change_threads) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_policy_control(processor_set_t pset, int flavor, processor_set_info_t policy_info, mach_msg_type_number_t count, boolean_t change) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_policy_disable(processor_set_t pset, int policy, boolean_t change_threads) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_policy_enable(processor_set_t pset, int policy) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_stack_usage(processor_set_t pset, unsigned int* totalp, vm_size_t* spacep, vm_size_t* residentp, vm_size_t* maxusagep, vm_offset_t* maxstackp) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_statistics(processor_set_t pset, int flavor, processor_set_info_t info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_tasks(processor_set_t pset, task_array_t* task_list, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_tasks_with_flavor(processor_set_t pset, mach_task_flavor_t flavor, task_array_t* task_list, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_set_threads(processor_set_t pset, thread_array_t* thread_list, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t processor_start_from_user(processor_t processor) {
	dtape_stub_unsafe();
};
