#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/memory.h>

#include <kern/task.h>
#include <kern/ipc_tt.h>
#include <kern/policy_internal.h>
#include <ipc/ipc_importance.h>
#include <kern/restartable.h>

#include <stdlib.h>

task_t kernel_task = NULL;

void dtape_task_init(void) {
	// this will assign to kernel_task
	if (!dtape_task_create(NULL, 0, NULL)) {
		panic("Failed to create kernel task");
	}
};

dtape_task_handle_t dtape_task_create(dtape_task_handle_t xparent_task, uint32_t nsid, void* context) {
	if (xparent_task == NULL && nsid == 0 && kernel_task) {
		dtape_task_t* task = dtape_task_for_xnu_task(kernel_task);

		// don't acquire an additional reference;
		// the managing Task instance acquires ownership of the kernel task
		//task_reference(kernel_task);

		if (task->context) {
			panic("The kernel task already has a context");
		} else {
			task->context = context;
		}
		return task;
	}

	dtape_task_t* parent_task = xparent_task;
	dtape_task_t* task = malloc(sizeof(dtape_task_t));
	if (!task) {
		return NULL;
	}

	task->context = context;
	task->saved_pid = nsid;
	memset(&task->xnu_task, 0, sizeof(task->xnu_task));

	// this next section uses code adapted from XNU's task_create_internal() in osfmk/kern/task.c

	os_ref_init(&task->xnu_task.ref_count, NULL);

	lck_mtx_init(&task->xnu_task.lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	queue_init(&task->xnu_task.threads);

	task->xnu_task.active = true;

	task->xnu_task.map = dtape_vm_map_create(task);

	ipc_task_init(&task->xnu_task, parent_task ? &parent_task->xnu_task : NULL);
	ipc_task_enable(&task->xnu_task);

	if (xparent_task == NULL && nsid == 0) {
		if (kernel_task) {
			panic("Another kernel task has been created");
		}

		kernel_task = &task->xnu_task;
	}

	return task;
};

void dtape_task_destroy(dtape_task_handle_t xtask) {
	dtape_task_t* task = xtask;

	if (os_ref_release(&task->xnu_task.ref_count) != 0) {
		panic("Duct-taped task over-retained or still in-use at destruction");
	}

	// this next section uses code adapted from XNU's task_deallocate() in osfmk/kern/task.c

	ipc_task_terminate(&task->xnu_task);

	dtape_vm_map_destroy(task->xnu_task.map);

	lck_mtx_destroy(&task->xnu_task.lock, LCK_GRP_NULL);
};

void task_deallocate(task_t task) {
	if (os_ref_release(&task->ref_count) == 0) {
		// the managing Task instance is supposed to have the last reference on the duct-taped task
		panic("Duct-taped task over-released");
	}
};

int pid_from_task(task_t xtask) {
	dtape_task_t* task = dtape_task_for_xnu_task(xtask);
	return task->saved_pid;
};

int proc_get_effective_task_policy(task_t task, int flavor) {
	dtape_stub();
	if (flavor == TASK_POLICY_ROLE) {
		return TASK_UNSPECIFIED;
	} else {
		panic("Unimplemented proc_get_effective_task_policy flavor: %d", flavor);
	}
};

int task_pid(task_t task) {
	return pid_from_task(task);
};

void task_id_token_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

void task_policy_update_complete_unlocked(task_t task, task_pend_token_t pend_token) {
	dtape_stub();
};

void task_port_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

void task_port_with_flavor_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

boolean_t task_suspension_notify(mach_msg_header_t* request_header) {
	dtape_stub();
	return FALSE;
};

void task_update_boost_locked(task_t task, boolean_t boost_active, task_pend_token_t pend_token) {
	dtape_stub();
};

void task_watchport_elem_deallocate(struct task_watchport_elem* watchport_elem) {
	dtape_stub();
};

kern_return_t task_create_suid_cred(task_t task, suid_cred_path_t path, suid_cred_uid_t uid, suid_cred_t* sc_p) {
	dtape_stub_unsafe();
};

kern_return_t task_create_identity_token(task_t task, task_id_token_t* tokenp) {
	dtape_stub_unsafe();
};

ipc_port_t convert_task_id_token_to_port(task_id_token_t token) {
	dtape_stub_unsafe();
};

task_id_token_t convert_port_to_task_id_token(ipc_port_t port) {
	dtape_stub_unsafe();
};

kern_return_t task_identity_token_get_task_port(task_id_token_t token, task_flavor_t flavor, ipc_port_t* portp) {
	dtape_stub_unsafe();
};

void task_id_token_release(task_id_token_t token) {
	dtape_stub_unsafe();
};

kern_return_t task_dyld_process_info_notify_deregister(task_t task, mach_port_name_t rcv_name) {
	dtape_stub_unsafe();
};

kern_return_t task_dyld_process_info_notify_register(task_t task, ipc_port_t sright) {
	dtape_stub_unsafe();
};

kern_return_t task_generate_corpse(task_t task, ipc_port_t* corpse_task_port) {
	dtape_stub_unsafe();
};

kern_return_t task_get_assignment(task_t task, processor_set_t* pset) {
	dtape_stub_unsafe();
};

kern_return_t task_get_state(task_t  task, int flavor, thread_state_t state, mach_msg_type_number_t* state_count) {
	dtape_stub_unsafe();
};

kern_return_t task_info_from_user(mach_port_t task_port, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t* task_info_count) {
	dtape_stub_unsafe();
};

kern_return_t task_inspect(task_inspect_t task_insp, task_inspect_flavor_t flavor, task_inspect_info_t info_out, mach_msg_type_number_t* size_in_out) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

bool task_is_driver(task_t task) {
	dtape_stub_safe();
	return false;
};

kern_return_t task_map_corpse_info(task_t task, task_t corpse_task, vm_address_t* kcd_addr_begin, uint32_t* kcd_size) {
	dtape_stub_unsafe();
};

kern_return_t task_map_corpse_info_64(task_t task, task_t corpse_task, mach_vm_address_t* kcd_addr_begin, mach_vm_size_t* kcd_size) {
	dtape_stub_unsafe();
};

void task_name_deallocate(task_name_t task_name) {
	dtape_stub_unsafe();
};

kern_return_t task_policy_get(task_t task, task_policy_flavor_t flavor, task_policy_t policy_info, mach_msg_type_number_t* count, boolean_t* get_default) {
	dtape_stub_unsafe();
};

void task_policy_get_deallocate(task_policy_get_t task_policy_get) {
	dtape_stub_unsafe();
};

kern_return_t task_policy_set(task_t task, task_policy_flavor_t flavor, task_policy_t policy_info, mach_msg_type_number_t count) {
	dtape_stub_unsafe();
};

void task_policy_set_deallocate(task_policy_set_t task_policy_set) {
	dtape_stub_unsafe();
};

kern_return_t task_purgable_info(task_t task, task_purgable_info_t* stats) {
	dtape_stub_unsafe();
};

void task_read_deallocate(task_read_t task_read) {
	dtape_stub_unsafe();
};

kern_return_t task_register_dyld_image_infos(task_t task, dyld_kernel_image_info_array_t infos_copy, mach_msg_type_number_t infos_len) {
	dtape_stub_unsafe();
};

kern_return_t task_register_dyld_shared_cache_image_info(task_t task, dyld_kernel_image_info_t cache_img, boolean_t no_cache, boolean_t private_cache) {
	dtape_stub_unsafe();
};

kern_return_t task_restartable_ranges_register(task_t task, task_restartable_range_t* ranges, mach_msg_type_number_t count) {
	dtape_stub_unsafe();
};

kern_return_t task_restartable_ranges_synchronize(task_t task) {
	dtape_stub_unsafe();
};

kern_return_t task_resume(task_t task) {
	dtape_stub_unsafe();
};

kern_return_t task_resume2(task_suspension_token_t task) {
	dtape_stub_unsafe();
};

kern_return_t task_set_exc_guard_behavior(task_t task, task_exc_guard_behavior_t behavior) {
	dtape_stub_unsafe();
};

kern_return_t task_set_info(task_t task, task_flavor_t flavor, task_info_t task_info_in, mach_msg_type_number_t task_info_count) {
	dtape_stub_unsafe();
};

kern_return_t task_set_phys_footprint_limit(task_t task, int new_limit_mb, int* old_limit_mb) {
	dtape_stub_unsafe();
};

kern_return_t task_set_state(task_t task, int flavor, thread_state_t state, mach_msg_type_number_t state_count) {
	dtape_stub_unsafe();
};

kern_return_t task_suspend(task_t task) {
	dtape_stub_unsafe();
};

kern_return_t task_suspend2(task_t task, task_suspension_token_t* suspend_token) {
	dtape_stub_unsafe();
};

void task_suspension_token_deallocate(task_suspension_token_t token) {
	dtape_stub_unsafe();
};

kern_return_t task_terminate(task_t task) {
	dtape_stub_unsafe();
};

kern_return_t task_threads_from_user(mach_port_t port, thread_act_array_t* threads_out, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t task_unregister_dyld_image_infos(task_t task, dyld_kernel_image_info_array_t infos_copy, mach_msg_type_number_t infos_len) {
	dtape_stub_unsafe();
};

// <copied from="xnu://7195.141.2/osfmk/kern/task_policy.c">

/*
 * Check if this task should donate importance.
 *
 * May be called without taking the task lock. In that case, donor status can change
 * so you must check only once for each donation event.
 */
boolean_t
task_is_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_donor(task->task_imp_base);
}

/*
 *      task_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given task. Policy must be a policy which is enabled for the
 *	processor set. Change contained threads if requested.
 */
kern_return_t
task_policy(
	__unused task_t                 task,
	__unused policy_t                       policy_id,
	__unused policy_base_t          base,
	__unused mach_msg_type_number_t count,
	__unused boolean_t                      set_limit,
	__unused boolean_t                      change)
{
	return KERN_FAILURE;
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/kern/task.c">

boolean_t
task_get_filter_msg_flag(
	task_t task)
{
	uint32_t flags = 0;

	if (!task) {
		return false;
	}

	flags = os_atomic_load(&task->t_flags, relaxed);
	return (flags & TF_FILTER_MSG) ? TRUE : FALSE;
}

/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	__unused task_t         task,
	__unused processor_set_t        new_pset,
	__unused boolean_t      assign_threads)
{
	return KERN_FAILURE;
}

/*
 *	task_assign_default:
 *
 *	Version of task_assign to assign to default processor set.
 */
kern_return_t
task_assign_default(
	task_t          task,
	boolean_t       assign_threads)
{
	return task_assign(task, &pset0, assign_threads);
}

kern_return_t
task_create(
	task_t                          parent_task,
	__unused ledger_port_array_t    ledger_ports,
	__unused mach_msg_type_number_t num_ledger_ports,
	__unused boolean_t              inherit_memory,
	__unused task_t                 *child_task)    /* OUT */
{
	if (parent_task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * No longer supported: too many calls assume that a task has a valid
	 * process attached.
	 */
	return KERN_FAILURE;
}

kern_return_t
task_get_dyld_image_infos(__unused task_t task,
    __unused dyld_kernel_image_info_array_t * dyld_images,
    __unused mach_msg_type_number_t * dyld_imagesCnt)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_get_exc_guard_behavior(
	task_t task,
	task_exc_guard_behavior_t *behaviorp)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	*behaviorp = task->task_exc_guard;
	return KERN_SUCCESS;
}

/* Placeholders for the task set/get voucher interfaces */
kern_return_t
task_get_mach_voucher(
	task_t                  task,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t           *voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	*voucher = NULL;
	return KERN_SUCCESS;
}

kern_return_t
task_set_mach_voucher(
	task_t                  task,
	ipc_voucher_t           __unused voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	return KERN_SUCCESS;
}

kern_return_t
task_swap_mach_voucher(
	__unused task_t         task,
	__unused ipc_voucher_t  new_voucher,
	ipc_voucher_t          *in_out_old_voucher)
{
	/*
	 * Currently this function is only called from a MIG generated
	 * routine which doesn't release the reference on the voucher
	 * addressed by in_out_old_voucher. To avoid leaking this reference,
	 * a call to release it has been added here.
	 */
	ipc_voucher_release(*in_out_old_voucher);
	return KERN_NOT_SUPPORTED;
}

/*
 *	task_inspect_deallocate:
 *
 *	Drop a task inspection reference.
 */
void
task_inspect_deallocate(
	task_inspect_t          task_inspect)
{
	return task_deallocate((task_t)task_inspect);
}

kern_return_t
task_register_dyld_set_dyld_state(__unused task_t task,
    __unused uint8_t dyld_state)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_register_dyld_get_process_state(__unused task_t task,
    __unused dyld_kernel_process_info_t * dyld_process_state)
{
	return KERN_NOT_SUPPORTED;
}

/*
 *	task_set_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given task. Policy can be any policy implemented by the
 *	processor set, whether enabled or not. Change contained threads
 *	if requested.
 */
kern_return_t
task_set_policy(
	__unused task_t                 task,
	__unused processor_set_t                pset,
	__unused policy_t                       policy_id,
	__unused policy_base_t          base,
	__unused mach_msg_type_number_t base_count,
	__unused policy_limit_t         limit,
	__unused mach_msg_type_number_t limit_count,
	__unused boolean_t                      change)
{
	return KERN_FAILURE;
}

kern_return_t
task_set_ras_pc(
	__unused task_t task,
	__unused vm_offset_t    pc,
	__unused vm_offset_t    endpc)
{
	return KERN_FAILURE;
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/kern/zalloc.c">

kern_return_t
task_zone_info(
	__unused task_t                                 task,
	__unused mach_zone_name_array_t *namesp,
	__unused mach_msg_type_number_t *namesCntp,
	__unused task_zone_info_array_t *infop,
	__unused mach_msg_type_number_t *infoCntp)
{
	return KERN_FAILURE;
}

// </copied>
