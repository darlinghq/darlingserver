#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>

#include <kern/task.h>
#include <kern/ipc_tt.h>
#include <kern/policy_internal.h>

#include <stdlib.h>

// stub
task_t kernel_task;

dtape_task_handle_t dtape_task_create(dtape_task_handle_t xparent_task, uint32_t nsid, void* context) {
	dtape_task_t* parent_task = xparent_task;
	dtape_task_t* task = malloc(sizeof(dtape_task_t));
	if (!task) {
		return NULL;
	}

	task->context = context;
	task->saved_pid = nsid;
	memset(&task->xnu_task, 0, sizeof(task->xnu_task));

	// this next section uses code adapted from XNU's task_create_internal() in osfmk/kern/task.c

	os_ref_init_count(&task->xnu_task.ref_count, NULL, 1);

	lck_mtx_init(&task->xnu_task.lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	queue_init(&task->xnu_task.threads);

	task->xnu_task.active = true;

	ipc_task_init(&task->xnu_task, parent_task ? &parent_task->xnu_task : NULL);
	ipc_task_enable(&task->xnu_task);

	return task;
};

void dtape_task_destroy(dtape_task_handle_t xtask) {
	dtape_task_t* task = xtask;

	if (os_ref_release(&task->xnu_task.ref_count) != 0) {
		panic("Duct-taped task over-retained or still in-use at destruction");
	}

	// this next section uses code adapted from XNU's task_deallocate() in osfmk/kern/task.c

	ipc_task_terminate(&task->xnu_task);

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
