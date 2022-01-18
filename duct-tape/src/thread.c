#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/hooks.h>

#include <kern/thread.h>
#include <kern/ipc_tt.h>
#include <kern/policy_internal.h>
#include <mach/thread_act.h>

#include <stdlib.h>

// stub
uint32_t sched_mach_factor = 0;

// stub
const qos_policy_params_t thread_qos_policy_params;

// stub
int thread_max = CONFIG_THREAD_MAX;

dtape_thread_handle_t dtape_thread_create(dtape_task_handle_t xtask, uint64_t nsid, void* context) {
	dtape_task_t* task = xtask;
	dtape_thread_t* thread = malloc(sizeof(dtape_thread_t));
	if (!thread) {
		return NULL;
	}

	thread->context = context;
	memset(&thread->xnu_thread, 0, sizeof(thread->xnu_thread));

	// this next section uses code adapted from XNU's thread_create_internal() in osfmk/kern/thread.c

	thread->xnu_thread.wait_result = THREAD_WAITING;
	thread->xnu_thread.options = THREAD_ABORTSAFE;
	thread->xnu_thread.state = TH_RUN;

	os_ref_init_count(&thread->xnu_thread.ref_count, NULL, 1);

	thread->xnu_thread.task = &task->xnu_task;

	thread_lock_init(&thread->xnu_thread);
	wake_lock_init(&thread->xnu_thread);

	lck_mtx_init(&thread->xnu_thread.mutex, LCK_GRP_NULL, LCK_ATTR_NULL);

	ipc_thread_init(&thread->xnu_thread, IPC_THREAD_INIT_NONE);

	task_lock(&task->xnu_task);

	task_reference_internal(&task->xnu_task);

	queue_enter(&task->xnu_task.threads, &thread->xnu_thread, thread_t, task_threads);
	task->xnu_task.thread_count++;

	os_atomic_inc(&task->xnu_task.active_thread_count, relaxed);

	thread->xnu_thread.active = true;

	thread->xnu_thread.turnstile = turnstile_alloc();

	task_unlock(&task->xnu_task);

	thread->xnu_thread.thread_id = nsid;

	return thread;
};

void dtape_thread_destroy(dtape_thread_handle_t xthread) {
	dtape_thread_t* thread = xthread;

	if (os_ref_release(&thread->xnu_thread.ref_count) != 0) {
		panic("Duct-taped thread over-retained or still in-use at destruction");
	}

	// this next section uses code adapted from XNU's thread_deallocate_complete() in osfmk/kern/thread.c

	ipc_thread_terminate(&thread->xnu_thread);

	if (thread->xnu_thread.turnstile) {
		turnstile_deallocate(thread->xnu_thread.turnstile);
	}

	if (IPC_VOUCHER_NULL != thread->xnu_thread.ith_voucher) {
		ipc_voucher_release(thread->xnu_thread.ith_voucher);
	}

	lck_mtx_destroy(&thread->xnu_thread.mutex, LCK_GRP_NULL);
};

void dtape_thread_entering(dtape_thread_handle_t thread_handle) {
	dtape_thread_t* thread = thread_handle;

	thread->xnu_thread.state = TH_RUN;
};

void dtape_thread_exiting(dtape_thread_handle_t thread_handle) {
	dtape_thread_t* thread = thread_handle;
};

thread_t current_thread(void) {
	dtape_thread_t* thread = dtape_hooks->current_thread();
	return &thread->xnu_thread;
};

void (thread_reference)(thread_t thread) {
	os_ref_retain(&thread->ref_count);
};

void thread_deallocate(thread_t thread) {
	// the managing Thread instance is supposed to have the last reference on the duct-taped thread
	os_ref_release_live(&thread->ref_count);
};

void thread_deallocate_safe(thread_t thread) {
	return thread_deallocate(thread);
};

static void thread_continuation_callback(dtape_thread_handle_t thread_handle) {
	dtape_thread_t* thread = thread_handle;
	thread_continue_t continuation = thread->xnu_thread.continuation;
	void* parameter = thread->xnu_thread.parameter;

	thread->xnu_thread.continuation = NULL;
	thread->xnu_thread.parameter = NULL;

	continuation(parameter, thread->xnu_thread.wait_result);

	thread_terminate(&thread->xnu_thread);
};

wait_result_t thread_block_parameter(thread_continue_t continuation, void* parameter) {
	dtape_thread_t* thread = dtape_hooks->current_thread();

	thread->xnu_thread.continuation = continuation;
	thread->xnu_thread.parameter = parameter;

	dtape_hooks->thread_suspend(thread->context, continuation ? thread_continuation_callback : NULL, NULL);

	// this should only ever be reached if there is no continuation
	assert(!continuation);

	return thread->xnu_thread.wait_result;
};

wait_result_t thread_block(thread_continue_t continuation) {
	return thread_block_parameter(continuation, NULL);
};

boolean_t thread_unblock(thread_t xthread, wait_result_t wresult) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	thread->xnu_thread.wait_result = wresult;
	dtape_hooks->thread_resume(thread->context);
	return TRUE;
};

kern_return_t thread_go(thread_t thread, wait_result_t wresult, waitq_options_t option) {
	return thread_unblock(thread, wresult) ? KERN_SUCCESS : KERN_FAILURE;
};

wait_result_t thread_mark_wait_locked(thread_t thread, wait_interrupt_t interruptible_orig) {
	dtape_stub();
	thread->state = TH_WAIT;
	thread->wait_result = THREAD_WAITING;
	return THREAD_WAITING;
};

kern_return_t thread_terminate(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	dtape_hooks->thread_terminate(thread->context);
	return KERN_SUCCESS;
};

void thread_sched_call(thread_t thread, sched_call_t call) {
	thread->sched_call = call;
};

kern_return_t kernel_thread_start_priority(thread_continue_t continuation, void* parameter, integer_t priority, thread_t* new_thread) {
	dtape_thread_handle_t thread_handle = dtape_hooks->thread_create_kernel();
	if (!thread_handle) {
		return KERN_FAILURE;
	}

	dtape_thread_t* thread = thread_handle;

	thread_reference(&thread->xnu_thread);
	*new_thread = &thread->xnu_thread;

	thread->xnu_thread.continuation = continuation;
	thread->xnu_thread.parameter = parameter;

	dtape_hooks->thread_start(thread->context, thread_continuation_callback);

	return KERN_SUCCESS;
};

void thread_set_thread_name(thread_t xthread, const char* name) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	thread->name = name;
};

void thread_guard_violation(thread_t thread, mach_exception_data_type_t code, mach_exception_data_type_t subcode, boolean_t fatal) {
	dtape_stub();
};

void thread_port_with_flavor_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

boolean_t thread_recompute_kernel_promotion_locked(thread_t thread) {
	dtape_stub_safe();
	return FALSE;
};

boolean_t thread_recompute_user_promotion_locked(thread_t thread) {
	dtape_stub_safe();
	return FALSE;
};

void thread_set_pending_block_hint(thread_t thread, block_hint_t block_hint) {
	dtape_stub_safe();
};

void thread_set_eager_preempt(thread_t thread) {
	dtape_stub_safe();
};

void sched_thread_promote_reason(thread_t thread, uint32_t reason, uintptr_t trace_obj) {
	dtape_stub_safe();
};

void sched_thread_unpromote_reason(thread_t thread, uint32_t reason, uintptr_t trace_obj) {
	dtape_stub_safe();
};

#if 0
kern_return_t thread_wakeup_prim(event_t event, boolean_t one_thread, wait_result_t result) {
	dtape_stub();
	return KERN_FAILURE;
};

kern_return_t thread_wakeup_thread(event_t event, thread_t thread) {
	dtape_stub();
	return KERN_FAILURE;
};

wait_result_t assert_wait_deadline(event_t event, wait_interrupt_t interruptible, uint64_t deadline) {
	dtape_stub();
	return THREAD_WAITING;
};

wait_result_t assert_wait_deadline_with_leeway(event_t event, wait_interrupt_t interruptible, wait_timeout_urgency_t urgency, uint64_t deadline, uint64_t leeway) {
	dtape_stub();
	return THREAD_WAITING;
};

kern_return_t clear_wait(thread_t thread, wait_result_t result) {
	dtape_stub();
	return KERN_FAILURE;
};
#endif

// ignore the lock timeout
#define LockTimeOutUsec UINT32_MAX

// <copied from="xnu://7195.141.2/osfmk/kern/sched_prim.c">

/*
 *	thread_wakeup_prim:
 *
 *	Common routine for thread_wakeup, thread_wakeup_with_result,
 *	and thread_wakeup_one.
 *
 */
kern_return_t
thread_wakeup_prim(
	event_t          event,
	boolean_t        one_thread,
	wait_result_t    result)
{
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *wq = global_eventq(event);

	if (one_thread) {
		return waitq_wakeup64_one(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
	} else {
		return waitq_wakeup64_all(wq, CAST_EVENT64_T(event), result, WAITQ_ALL_PRIORITIES);
	}
}

/*
 * Wakeup a specified thread if and only if it's waiting for this event
 */
kern_return_t
thread_wakeup_thread(
	event_t         event,
	thread_t        thread)
{
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	if (__improbable(thread == THREAD_NULL)) {
		panic("%s() called with THREAD_NULL", __func__);
	}

	struct waitq *wq = global_eventq(event);

	return waitq_wakeup64_thread(wq, CAST_EVENT64_T(event), thread, THREAD_AWAKENED);
}

/*
 *	assert_wait:
 *
 *	Assert that the current thread is about to go to
 *	sleep until the specified event occurs.
 */
wait_result_t
assert_wait(
	event_t                         event,
	wait_interrupt_t        interruptible)
{
	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(event), 0, 0, 0, 0);

	struct waitq *waitq;
	waitq = global_eventq(event);
	return waitq_assert_wait64(waitq, CAST_EVENT64_T(event), interruptible, TIMEOUT_WAIT_FOREVER);
}

wait_result_t
assert_wait_timeout(
	event_t                         event,
	wait_interrupt_t        interruptible,
	uint32_t                        interval,
	uint32_t                        scale_factor)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	uint64_t                        deadline;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	clock_interval_to_deadline(interval, scale_factor, &deadline);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
	    interruptible,
	    TIMEOUT_URGENCY_SYS_NORMAL,
	    deadline, TIMEOUT_NO_LEEWAY,
	    thread);

	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

wait_result_t
assert_wait_deadline(
	event_t                         event,
	wait_interrupt_t        interruptible,
	uint64_t                        deadline)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
	    interruptible,
	    TIMEOUT_URGENCY_SYS_NORMAL, deadline,
	    TIMEOUT_NO_LEEWAY, thread);
	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

wait_result_t
assert_wait_deadline_with_leeway(
	event_t                         event,
	wait_interrupt_t        interruptible,
	wait_timeout_urgency_t  urgency,
	uint64_t                        deadline,
	uint64_t                        leeway)
{
	thread_t                        thread = current_thread();
	wait_result_t           wresult;
	spl_t                           s;

	if (__improbable(event == NO_EVENT)) {
		panic("%s() called with NO_EVENT", __func__);
	}

	struct waitq *waitq;
	waitq = global_eventq(event);

	s = splsched();
	waitq_lock(waitq);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(event), interruptible, deadline, 0, 0);

	wresult = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
	    interruptible,
	    urgency, deadline, leeway,
	    thread);
	waitq_unlock(waitq);
	splx(s);
	return wresult;
}

/*
 *	Routine: clear_wait_internal
 *
 *		Clear the wait condition for the specified thread.
 *		Start the thread executing if that is appropriate.
 *	Arguments:
 *		thread		thread to awaken
 *		result		Wakeup result the thread should see
 *	Conditions:
 *		At splsched
 *		the thread is locked.
 *	Returns:
 *		KERN_SUCCESS		thread was rousted out a wait
 *		KERN_FAILURE		thread was waiting but could not be rousted
 *		KERN_NOT_WAITING	thread was not waiting
 */
__private_extern__ kern_return_t
clear_wait_internal(
	thread_t                thread,
	wait_result_t   wresult)
{
	uint32_t        i = LockTimeOutUsec;
	struct waitq *waitq = thread->waitq;

	do {
		if (wresult == THREAD_INTERRUPTED && (thread->state & TH_UNINT)) {
			return KERN_FAILURE;
		}

		if (waitq != NULL) {
			if (!waitq_pull_thread_locked(waitq, thread)) {
				thread_unlock(thread);
				delay(1);
				if (i > 0 && !machine_timeout_suspended()) {
					i--;
				}
				thread_lock(thread);
				if (waitq != thread->waitq) {
					return KERN_NOT_WAITING;
				}
				continue;
			}
		}

		/* TODO: Can we instead assert TH_TERMINATE is not set?  */
		if ((thread->state & (TH_WAIT | TH_TERMINATE)) == TH_WAIT) {
			return thread_go(thread, wresult, WQ_OPTION_NONE);
		} else {
			return KERN_NOT_WAITING;
		}
	} while (i > 0);

	panic("clear_wait_internal: deadlock: thread=%p, wq=%p, cpu=%d\n",
	    thread, waitq, cpu_number());

	return KERN_FAILURE;
}


/*
 *	clear_wait:
 *
 *	Clear the wait condition for the specified thread.  Start the thread
 *	executing if that is appropriate.
 *
 *	parameters:
 *	  thread		thread to awaken
 *	  result		Wakeup result the thread should see
 */
kern_return_t
clear_wait(
	thread_t                thread,
	wait_result_t   result)
{
	kern_return_t ret;
	spl_t           s;

	s = splsched();
	thread_lock(thread);
	ret = clear_wait_internal(thread, result);
	thread_unlock(thread);
	splx(s);
	return ret;
}

// </copied>
