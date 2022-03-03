#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/psynch.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/task.h>
#include <kern/ipc_tt.h>
#include <kern/policy_internal.h>
#include <ipc/ipc_importance.h>
#include <kern/restartable.h>
#include <kern/sync_sema.h>
#include <mach/mach_traps.h>
#include <mach/mach_port.h>

#include <stdlib.h>

task_t kernel_task = NULL;

void dtape_task_init(void) {
	// this will assign to kernel_task
	dserver_rpc_architecture_t arch = dserver_rpc_architecture_invalid;

#if __x86_64__
	arch = dserver_rpc_architecture_x86_64;
#elif __i386__
	arch = dserver_rpc_architecture_i386;
#elif __aarch64__
	arch = dserver_rpc_architecture_arm64;
#elif __arm__
	arch = dserver_rpc_architecture_arm32;
#else
	#error Unknown architecture
#endif

	if (!dtape_task_create(NULL, 0, NULL, arch)) {
		panic("Failed to create kernel task");
	}
};

dtape_task_t* dtape_task_create(dtape_task_t* parent_task, uint32_t nsid, void* context, dserver_rpc_architecture_t architecture) {
	if (parent_task == NULL && nsid == 0 && kernel_task) {
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

	dtape_task_t* task = malloc(sizeof(dtape_task_t));
	if (!task) {
		return NULL;
	}

	task->context = context;
	task->saved_pid = nsid;
	task->architecture = architecture;
	task->has_sigexc = false;
	memset(&task->xnu_task, 0, sizeof(task->xnu_task));

	// this next section uses code adapted from XNU's task_create_internal() in osfmk/kern/task.c

	os_ref_init(&task->xnu_task.ref_count, NULL);

	lck_mtx_init(&task->xnu_task.lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	queue_init(&task->xnu_task.threads);

	task->xnu_task.active = true;

	task->xnu_task.map = dtape_vm_map_create(task);

	queue_init(&task->xnu_task.semaphore_list);

	ipc_task_init(&task->xnu_task, parent_task ? &parent_task->xnu_task : NULL);

	if (parent_task) {
		task_importance_init_from_parent(&task->xnu_task, &parent_task->xnu_task);
	}

	// this is a hack to force all tasks to have an IPC importance structure associated with them
	// since i'm not sure where it's normally acquired in XNU.
	// (this is necessary ipc_importance_send() needs the task to have a valid `task_imp_base`)
	if (task->xnu_task.task_imp_base == IIT_NULL) {
		ipc_importance_for_task(&task->xnu_task, false);
	}

	if (parent_task != NULL) {
		task->xnu_task.sec_token = parent_task->xnu_task.sec_token;
		task->xnu_task.audit_token = parent_task->xnu_task.audit_token;
	} else {
		task->xnu_task.sec_token = KERNEL_SECURITY_TOKEN;
		task->xnu_task.audit_token = KERNEL_AUDIT_TOKEN;
	}

	task->xnu_task.audit_token.val[5] = task->saved_pid;

	if (architecture == dserver_rpc_architecture_x86_64 || architecture == dserver_rpc_architecture_arm64) {
		task_set_64Bit_addr(&task->xnu_task);
		task_set_64Bit_data(&task->xnu_task);
	}

	ipc_task_enable(&task->xnu_task);

	dtape_psynch_task_init(task);

	if (parent_task == NULL && nsid == 0) {
		if (kernel_task) {
			panic("Another kernel task has been created");
		}

		kernel_task = &task->xnu_task;
	}

	return task;
};

void dtape_task_destroy(dtape_task_t* task) {
	if (IIT_NULL != task->xnu_task.task_imp_base) {
		ipc_importance_disconnect_task(&task->xnu_task);
	}

	if (os_ref_release(&task->xnu_task.ref_count) != 0) {
		panic("Duct-taped task over-retained or still in-use at destruction");
	}

	dtape_psynch_task_destroy(task);

	// this next section uses code adapted from XNU's task_deallocate() in osfmk/kern/task.c

	semaphore_destroy_all(&task->xnu_task);

	task_lock(&task->xnu_task);
	task->xnu_task.active = false;
	ipc_task_disable(&task->xnu_task);
	task_unlock(&task->xnu_task);

	ipc_task_terminate(&task->xnu_task);

	dtape_vm_map_destroy(task->xnu_task.map);

	lck_mtx_destroy(&task->xnu_task.lock, LCK_GRP_NULL);

	free(task);
};

void dtape_task_uidgid(dtape_task_t* task, int new_uid, int new_gid, int* old_uid, int* old_gid) {
	task_lock(&task->xnu_task);
	if (old_uid) {
		*old_uid = task->xnu_task.audit_token.val[1];
	}
	if (old_gid) {
		*old_gid = task->xnu_task.audit_token.val[2];
	}
	if (new_uid >= 0) {
		task->xnu_task.audit_token.val[1] = new_uid;
	}
	if (new_gid >= 0) {
		task->xnu_task.audit_token.val[2] = new_gid;
	}
	task_unlock(&task->xnu_task);
};

void dtape_task_retain(dtape_task_t* task) {
	task_reference(&task->xnu_task);
};

void dtape_task_release(dtape_task_t* task) {
	task_deallocate(&task->xnu_task);
};

void dtape_task_dying(dtape_task_t* task) {
	// nothing for now
};

void task_deallocate(task_t task) {
	// the managing Task instance is supposed to have the last reference on the duct-taped task
	os_ref_release_live(&task->ref_count);
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

kern_return_t task_info(task_t xtask, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t* task_info_count) {
	dtape_task_t* task = dtape_task_for_xnu_task(xtask);

	switch (flavor) {
		case TASK_BASIC_INFO_32:
		case TASK_BASIC_INFO_64:
		case MACH_TASK_BASIC_INFO: {
			uint64_t utimeus;
			uint64_t stimeus;
			dtape_memory_info_t mem_info;

			dtape_hooks->task_get_memory_info(task->context, &mem_info);

			dtape_log_debug("%s: TODO: fetch utimeus and stimeus somehow", __FUNCTION__);
			utimeus = 0;
			stimeus = 0;

			if (flavor == TASK_BASIC_INFO_32) {
				struct task_basic_info_32* info = (void*)task_info_out;

				if (*task_info_count < TASK_BASIC_INFO_32_COUNT) {
					return KERN_INVALID_ARGUMENT;
				}

				*task_info_count = TASK_BASIC_INFO_32_COUNT;

				info->suspend_count = task->xnu_task.user_stop_count;
				info->virtual_size = mem_info.virtual_size;
				info->resident_size = mem_info.resident_size;
				info->user_time.seconds = utimeus / USEC_PER_SEC;
				info->user_time.microseconds = utimeus % USEC_PER_SEC;
				info->system_time.seconds = stimeus / USEC_PER_SEC;
				info->system_time.microseconds = stimeus % USEC_PER_SEC;
				info->policy = 0;
			} else if (flavor == TASK_BASIC_INFO_64) {
				struct task_basic_info_64* info = (void*)task_info_out;

				if (*task_info_count < TASK_BASIC_INFO_64_COUNT) {
					return KERN_INVALID_ARGUMENT;
				}

				*task_info_count = TASK_BASIC_INFO_64_COUNT;

				info->suspend_count = task->xnu_task.user_stop_count;
				info->virtual_size = mem_info.virtual_size;
				info->resident_size = mem_info.resident_size;
				info->user_time.seconds = utimeus / USEC_PER_SEC;
				info->user_time.microseconds = utimeus % USEC_PER_SEC;
				info->system_time.seconds = stimeus / USEC_PER_SEC;
				info->system_time.microseconds = stimeus % USEC_PER_SEC;
				info->policy = 0;
			} else {
				struct mach_task_basic_info* info = (void*)task_info_out;

				if (*task_info_count < MACH_TASK_BASIC_INFO_COUNT) {
					return KERN_INVALID_ARGUMENT;
				}

				*task_info_count = MACH_TASK_BASIC_INFO_COUNT;

				info->suspend_count = task->xnu_task.user_stop_count;
				info->virtual_size = mem_info.virtual_size;
				info->resident_size = mem_info.resident_size;
				info->user_time.seconds = utimeus / USEC_PER_SEC;
				info->user_time.microseconds = utimeus % USEC_PER_SEC;
				info->system_time.seconds = stimeus / USEC_PER_SEC;
				info->system_time.microseconds = stimeus % USEC_PER_SEC;
				info->policy = 0;
			}

			return KERN_SUCCESS;
		};

		default:
			dtape_stub_unsafe("unimplemented flavor");
	}
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
	dtape_stub_safe();
	return KERN_SUCCESS;
};

void task_policy_set_deallocate(task_policy_set_t task_policy_set) {
	return task_deallocate((task_t)task_policy_set);
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

static kern_return_t task_for_pid_internal(mach_port_name_t target_tport, int pid, uintptr_t t, bool task_name) {
	kern_return_t kr = KERN_FAILURE;
	task_t receiving_task = TASK_NULL;
	dtape_task_t* looked_up_task = NULL;
	ipc_port_t right = IPC_PORT_NULL;
	mach_port_name_t out_name = MACH_PORT_NULL;

	receiving_task = port_name_to_task(target_tport);
	if (receiving_task == TASK_NULL) {
		goto out;
	}

	looked_up_task = dtape_hooks->task_lookup(pid, true, true);
	if (!looked_up_task) {
		goto out;
	}

	if (task_name) {
		right = convert_task_name_to_port(&looked_up_task->xnu_task);
	} else {
		if (&looked_up_task->xnu_task == current_task()) {
			right = convert_task_to_port_pinned(&looked_up_task->xnu_task);
		} else {
			right = convert_task_to_port(&looked_up_task->xnu_task);
		}
	}

	// consumed by convert_task{,_name}_to_port{,_pinned}
	looked_up_task = NULL;

	if (right == IPC_PORT_NULL) {
		goto out;
	}

	out_name = ipc_port_copyout_send(right, receiving_task->itk_space);

	// consumed by ipc_port_copyout_send
	right = IPC_PORT_NULL;

	if (!MACH_PORT_VALID(out_name)) {
		goto out;
	}

	if (copyout(&out_name, t, sizeof(out_name))) {
		goto out;
	}

	// consumed by copyout
	out_name = MACH_PORT_NULL;

	kr = KERN_SUCCESS;

out:
	if (MACH_PORT_VALID(out_name)) {
		mach_port_deallocate(receiving_task->itk_space, out_name);
	}
	if (right != IPC_PORT_NULL) {
		ipc_port_release_send(right);
	}
	if (looked_up_task) {
		dtape_task_release(looked_up_task);
	}
	if (receiving_task != TASK_NULL) {
		task_deallocate(receiving_task);
	}
	return kr;
};

kern_return_t task_for_pid(struct task_for_pid_args* args) {
	return task_for_pid_internal(args->target_tport, args->pid, args->t, false);
};

kern_return_t task_name_for_pid(struct task_name_for_pid_args* args) {
	return task_for_pid_internal(args->target_tport, args->pid, args->t, true);
};

kern_return_t pid_for_task(struct pid_for_task_args* args) {
	kern_return_t kr = KERN_FAILURE;
	task_t converted_task = TASK_NULL;
	int pid = -1;

	converted_task = port_name_to_task_name(args->t);
	if (converted_task == TASK_NULL) {
		goto out;
	}

	pid = task_pid(converted_task);

	if (pid < 0) {
		goto out;
	}

	if (copyout(&pid, args->pid, sizeof(pid))) {
		goto out;
	}

	kr = KERN_SUCCESS;

out:
	if (converted_task != TASK_NULL) {
		task_deallocate(converted_task);
	}
	return kr;
};

boolean_t task_is_exec_copy(task_t task) {
	dtape_stub_safe();
	return FALSE;
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

/*
 * Query the status of the task's donor mark.
 */
boolean_t
task_is_marked_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_donor(task->task_imp_base);
}

/*
 * Query the status of the task's live donor and donor mark.
 */
boolean_t
task_is_marked_live_importance_donor(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_live_donor(task->task_imp_base);
}

/*
 * Query the task's receiver mark.
 */
boolean_t
task_is_marked_importance_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_receiver(task->task_imp_base);
}

/*
 * This routine may be called without holding task lock
 * since the value of de-nap receiver can never be unset.
 */
boolean_t
task_is_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_denap_receiver(task->task_imp_base);
}

/*
 * Query the task's de-nap receiver mark.
 */
boolean_t
task_is_marked_importance_denap_receiver(task_t task)
{
	if (task->task_imp_base == IIT_NULL) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_denap_receiver(task->task_imp_base);
}

void
task_importance_init_from_parent(task_t new_task, task_t parent_task)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_task_t new_task_imp = IIT_NULL;

	new_task->task_imp_base = NULL;
	if (!parent_task) {
		return;
	}

	if (task_is_marked_importance_donor(parent_task)) {
		new_task_imp = ipc_importance_for_task(new_task, FALSE);
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_donor(new_task_imp, TRUE);
	}
	if (task_is_marked_live_importance_donor(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_live_donor(new_task_imp, TRUE);
	}
	/* Do not inherit 'receiver' on fork, vfexec or true spawn */
	if (task_is_exec_copy(new_task) &&
	    task_is_marked_importance_receiver(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_receiver(new_task_imp, TRUE);
	}
	if (task_is_marked_importance_denap_receiver(parent_task)) {
		if (IIT_NULL == new_task_imp) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
		}
		assert(IIT_NULL != new_task_imp);
		ipc_importance_task_mark_denap_receiver(new_task_imp, TRUE);
	}
	if (IIT_NULL != new_task_imp) {
		assert(new_task->task_imp_base == new_task_imp);
		ipc_importance_task_release(new_task_imp);
	}
#endif /* IMPORTANCE_INHERITANCE */
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

/*
 * This routine finds a thread in a task by its unique id
 * Returns a referenced thread or THREAD_NULL if the thread was not found
 *
 * TODO: This is super inefficient - it's an O(threads in task) list walk!
 *       We should make a tid hash, or transition all tid clients to thread ports
 *
 * Precondition: No locks held (will take task lock)
 */
thread_t
task_findtid(task_t task, uint64_t tid)
{
	thread_t self           = current_thread();
	thread_t found_thread   = THREAD_NULL;
	thread_t iter_thread    = THREAD_NULL;

	/* Short-circuit the lookup if we're looking up ourselves */
	if (tid == self->thread_id || tid == TID_NULL) {
		assert(self->task == task);

		thread_reference(self);

		return self;
	}

	task_lock(task);

	queue_iterate(&task->threads, iter_thread, thread_t, task_threads) {
		if (iter_thread->thread_id == tid) {
			found_thread = iter_thread;
			thread_reference(found_thread);
			break;
		}
	}

	task_unlock(task);

	return found_thread;
}

/*
 * task_info_from_user
 *
 * When calling task_info from user space,
 * this function will be executed as mig server side
 * instead of calling directly into task_info.
 * This gives the possibility to perform more security
 * checks on task_port.
 *
 * In the case of TASK_DYLD_INFO, we require the more
 * privileged task_read_port not the less-privileged task_name_port.
 *
 */
kern_return_t
task_info_from_user(
	mach_port_t             task_port,
	task_flavor_t           flavor,
	task_info_t             task_info_out,
	mach_msg_type_number_t  *task_info_count)
{
	task_t task;
	kern_return_t ret;

	if (flavor == TASK_DYLD_INFO) {
		task = convert_port_to_task_read(task_port);
	} else {
		task = convert_port_to_task_name(task_port);
	}

	ret = task_info(task, flavor, task_info_out, task_info_count);

	task_deallocate(task);

	return ret;
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
