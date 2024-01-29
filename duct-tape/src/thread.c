#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/psynch.h>

#include <kern/thread.h>
#include <kern/ipc_tt.h>
#include <kern/policy_internal.h>
#include <mach/thread_act.h>
#include <sys/systm.h>
#include <sys/ux_exception.h>

#include <stdlib.h>

#include <rtsig.h>

#define LINUX_ENOSYS 38
#define LINUX_EFAULT 14

#define LINUX_SI_USER 0
#define LINUX_SI_KERNEL 0x80
#define LINUX_TRAP_HWBKPT 4

#define LINUX_SIGSEGV 11
#define LINUX_SIGBUS 7
#define LINUX_SIGILL 4
#define LINUX_SIGFPE 8
#define LINUX_SIGTRAP 5

// stub
uint32_t sched_mach_factor = 0;

// stub
const qos_policy_params_t thread_qos_policy_params;

// stub
int thread_max = CONFIG_THREAD_MAX;

kern_return_t thread_set_state(register thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t state_count);

kern_return_t thread_get_state(thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t* state_count);

dtape_thread_t* dtape_thread_create(dtape_task_t* task, uint64_t nsid, void* context) {
	dtape_thread_t* thread = malloc(sizeof(dtape_thread_t));
	if (!thread) {
		return NULL;
	}

	thread->context = context;
	thread->processing_signal = false;
	thread->name = NULL;
	thread->waiting_suspended = false;
	LIST_INIT(&thread->user_states);
	dtape_mutex_init(&thread->suspension_mutex);
	dtape_condvar_init(&thread->suspension_condvar);
	memset(&thread->xnu_thread, 0, sizeof(thread->xnu_thread));
	memset(&thread->kwe, 0, sizeof(thread->kwe));

	memset(&thread->default_state, 0, sizeof(thread->default_state));
	LIST_INSERT_HEAD(&thread->user_states, &thread->default_state, link);

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

	thread->xnu_thread.map = task->xnu_task.map;

	timer_call_setup(&thread->xnu_thread.wait_timer, thread_timer_expire, &thread->xnu_thread);

	dtape_psynch_thread_init(thread);

	return thread;
};

void dtape_thread_destroy(dtape_thread_t* thread) {
	dtape_log_debug("%llu: thread being destroyed", thread->xnu_thread.thread_id);

	dtape_psynch_thread_destroy(thread);

	// this next section uses code adapted from XNU's thread_deallocate_complete() in osfmk/kern/thread.c

	ipc_thread_disable(&thread->xnu_thread);
	ipc_thread_terminate(&thread->xnu_thread);

	if (thread->xnu_thread.turnstile) {
		turnstile_deallocate(thread->xnu_thread.turnstile);
	}

	if (IPC_VOUCHER_NULL != thread->xnu_thread.ith_voucher) {
		ipc_voucher_release(thread->xnu_thread.ith_voucher);
	}

	thread_lock(&thread->xnu_thread);

	/*
	 *	Cancel wait timer, and wait for
	 *	concurrent expirations.
	 */
	if (thread->xnu_thread.wait_timer_is_set) {
		thread->xnu_thread.wait_timer_is_set = FALSE;

		if (timer_call_cancel(&thread->xnu_thread.wait_timer)) {
			thread->xnu_thread.wait_timer_active--;
		}
	}

	while (thread->xnu_thread.wait_timer_active > 0);

	// pull the thread from any waitqs it might have been waiting on
	thread->xnu_thread.state |= TH_TERMINATE;
	thread->xnu_thread.state &= ~(TH_UNINT);
	clear_wait_internal(&thread->xnu_thread, THREAD_INTERRUPTED);

	thread_unlock(&thread->xnu_thread);

	lck_mtx_destroy(&thread->xnu_thread.mutex, LCK_GRP_NULL);

	// remove this thread from the task's thread list
	task_lock(thread->xnu_thread.task);
	queue_remove(&thread->xnu_thread.task->threads, &thread->xnu_thread, thread_t, task_threads);
	thread->xnu_thread.task->thread_count--;
	task_unlock(thread->xnu_thread.task);

	task_deallocate(thread->xnu_thread.task);

	dtape_hooks->thread_context_dispose(thread->context);

	free(thread);
};

void dtape_thread_entering(dtape_thread_t* thread) {
	// if the thread is entering, it cannot be waiting
	thread->xnu_thread.state &= ~(TH_WAIT | TH_UNINT);
	thread->xnu_thread.state |= TH_RUN;
	thread->xnu_thread.block_hint = kThreadWaitNone;
};

void dtape_thread_exiting(dtape_thread_t* thread) {
	thread->xnu_thread.state &= ~TH_RUN;
};

void dtape_thread_set_handles(dtape_thread_t* thread, uintptr_t pthread_handle, uintptr_t dispatch_qaddr) {
	thread_lock(&thread->xnu_thread);
	thread->pthread_handle = pthread_handle;
	thread->dispatch_qaddr = dispatch_qaddr;
	thread_unlock(&thread->xnu_thread);
};

dtape_thread_t* dtape_thread_for_port(uint32_t thread_port) {
	thread_t xnu_thread = port_name_to_thread(thread_port, PORT_TO_THREAD_NONE);
	if (!xnu_thread) {
		return NULL;
	}
	// port_name_to_thread returns a reference on the thread upon success.
	// because we cannot take a reference on the duct-taped thread owner,
	// this reference is meaningless. therefore, we drop it.
	// we entrust our caller with the responsibility of ensuring it remains alive.
	thread_deallocate(xnu_thread);
	return dtape_thread_for_xnu_thread(xnu_thread);
};

void* dtape_thread_context(dtape_thread_t* thread) {
	return thread->context;
};

int dtape_thread_load_state_from_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address) {
	dtape_task_t* task = dtape_task_for_thread(thread);

	if (task->architecture == dserver_rpc_architecture_x86_64) {
#if defined(__x86_64__) || defined(__i386__)
		x86_thread_state64_t tstate;
		x86_float_state64_t fstate;

		if (copyin(thread_state_address, &tstate, sizeof(tstate)) || copyin(float_state_address, &fstate, sizeof(fstate))) {
			return -LINUX_EFAULT;
		}

		thread_set_state(current_thread(), x86_THREAD_STATE64, (thread_state_t) &tstate, x86_THREAD_STATE64_COUNT);
		thread_set_state(current_thread(), x86_FLOAT_STATE64, (thread_state_t) &fstate, x86_FLOAT_STATE64_COUNT);
#else
	__builtin_unreachable();
#endif
	} else if (task->architecture == dserver_rpc_architecture_i386) {
#if defined(__x86_64__) || defined(__i386__)
		x86_thread_state32_t tstate;
		x86_float_state32_t fstate;

		if (copyin(thread_state_address, &tstate, sizeof(tstate)) || copyin(float_state_address, &fstate, sizeof(fstate))) {
			return -LINUX_EFAULT;
		}

		thread_set_state(current_thread(), x86_THREAD_STATE32, (thread_state_t) &tstate, x86_THREAD_STATE32_COUNT);
		thread_set_state(current_thread(), x86_FLOAT_STATE32, (thread_state_t) &fstate, x86_FLOAT_STATE32_COUNT);
#else
	__builtin_unreachable();
#endif
	} else if (task->architecture == dserver_rpc_architecture_arm64) {
#if __aarch64__
		arm_thread_state64_t tstate;
		// arm_neon_state64_t nstate;

		#warning "TODO: Implement neon/float state"
		//  || copyin(float_state_address, &fstate, sizeof(fstate))
		if (copyin(thread_state_address, &tstate, sizeof(tstate))) {
			return -LINUX_EFAULT;
		}

		thread_set_state(current_thread(), ARM_THREAD_STATE64, (thread_state_t) &tstate, ARM_THREAD_STATE64_COUNT);
		// thread_set_state(current_thread(), ARM_NEON_STATE64, (thread_state_t) &nstate, ARM_NEON_STATE64_COUNT);
#else
	__builtin_unreachable();
#endif
	} else {
		dtape_log_error("dtape_thread_load_state_from_user() unimplemented for architecture: %d", task->architecture);
		return -LINUX_ENOSYS;
	}

	return 0;
};

int dtape_thread_save_state_to_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address) {
	dtape_task_t* task = dtape_task_for_thread(thread);

	if (task->architecture == dserver_rpc_architecture_x86_64) {
#if defined(__x86_64__) || defined(__i386__)
		x86_thread_state64_t tstate;
		x86_float_state64_t fstate;
		mach_msg_type_number_t count;

		count = x86_THREAD_STATE64_COUNT;
		thread_get_state(current_thread(), x86_THREAD_STATE64, (thread_state_t) &tstate, &count);

		count = x86_FLOAT_STATE64_COUNT;
		thread_get_state(current_thread(), x86_FLOAT_STATE64, (thread_state_t) &fstate, &count);

		if (copyout(&tstate, thread_state_address, sizeof(tstate)) || copyout(&fstate, float_state_address, sizeof(fstate))) {
			return -LINUX_EFAULT;
		}
#else
	__builtin_unreachable();
#endif
	} else if (task->architecture == dserver_rpc_architecture_i386) {
#if defined(__x86_64__) || defined(__i386__)
		x86_thread_state32_t tstate;
		x86_float_state32_t fstate;
		mach_msg_type_number_t count;

		count = x86_THREAD_STATE32_COUNT;
		thread_get_state(current_thread(), x86_THREAD_STATE32, (thread_state_t) &tstate, &count);

		count = x86_FLOAT_STATE32_COUNT;
		thread_get_state(current_thread(), x86_FLOAT_STATE32, (thread_state_t) &fstate, &count);

		if (copyout(&tstate, thread_state_address, sizeof(tstate)) || copyout(&fstate, float_state_address, sizeof(fstate))) {
			return -LINUX_EFAULT;
		}
#else
	__builtin_unreachable();
#endif
	} else if (task->architecture == dserver_rpc_architecture_arm64) {
#if __aarch64__
		arm_thread_state64_t tstate;
		// arm_neon_state64_t nstate;
		mach_msg_type_number_t count;

		count = ARM_THREAD_STATE64_COUNT;
		thread_get_state(current_thread(), ARM_THREAD_STATE64, (thread_state_t) &tstate, &count);

		#warning "TODO: Implement neon/float state"
		// count = ARM_NEON_STATE64_COUNT;
		// thread_get_state(current_thread(), ARM_THREAD_STATE64, (thread_state_t) &nstate, &count);

		// || copyout(&nstate, float_state_address, sizeof(nstate))
		if (copyout(&tstate, thread_state_address, sizeof(tstate))) {
			return -LINUX_EFAULT;
		}
#else
	__builtin_unreachable();
#endif
	} else {
		dtape_log_error("dtape_thread_save_state_to_user() unimplemented for architecture: %d", task->architecture);
		return -LINUX_ENOSYS;
	}

	return 0;
};

void dtape_thread_process_signal(dtape_thread_t* thread, int bsd_signal_number, int linux_signal_number, int code, uintptr_t signal_address) {
	mach_exception_data_type_t codes[EXCEPTION_CODE_MAX] = { 0, 0 };
	dtape_task_t* task = dtape_task_for_thread(thread);

	thread->processing_signal = true;

	if (code == LINUX_SI_USER) {
		if (task->has_sigexc) {
			codes[0] = EXC_SOFT_SIGNAL;
			codes[1] = bsd_signal_number;
			bsd_exception(EXC_SOFTWARE, codes, 2);
		} else {
			dtape_hooks->thread_set_pending_signal(thread->context, bsd_signal_number);
		}

		goto out;
	}

	int mach_exception = 0;
	switch (linux_signal_number) {
		case LINUX_SIGSEGV: // KERN_INVALID_ADDRESS
			mach_exception = EXC_BAD_ACCESS;
			codes[0] = KERN_INVALID_ADDRESS;
			codes[1] = signal_address;
			break;
		case LINUX_SIGBUS:
			mach_exception = EXC_BAD_ACCESS;
#if defined(__x86_64__) || defined(__i386__)
			codes[0] = EXC_I386_ALIGNFLT;
#elif defined(__aarch64__)
			codes[0] = EXC_ARM_DA_ALIGN;
#else
#error "Missing LINUX_SIGBUS conversion"
#endif
			break;
		case LINUX_SIGILL:
			mach_exception = EXC_BAD_INSTRUCTION;
#if defined(__x86_64__) || defined(__i386__)
			codes[0] = EXC_I386_INVOP;
#elif defined(__aarch64__)
			codes[0] = EXC_ARM_UNDEFINED;
#else
#error "Missing LINUX_SIGILL conversion"
#endif
			break;
		case LINUX_SIGFPE:
			mach_exception = EXC_ARITHMETIC;
			codes[0] = code;
			break;
		case LINUX_SIGTRAP:
			mach_exception = EXC_BREAKPOINT;
#if defined(__x86_64__) || defined(__i386__)
			codes[0] = (code == LINUX_SI_KERNEL) ? EXC_I386_BPT : EXC_I386_SGL;
#elif defined(__aarch64__)
			codes[0] = EXC_ARM_BREAKPOINT;
#else
#error "Missing LINUX_SIGTRAP conversion"
#endif

			if (code == LINUX_TRAP_HWBKPT) {
#if 0
				codes[1] = thread->triggered_watchpoint_address;
#else
				dtape_stub("LINUX_TRAP_HWBKPT");
				codes[1] = 0;
#endif
			}
			break;
		/*
		case LINUX_SIGSYS:
			mach_exception = EXC_SOFTWARE;
			if (codes[0] == 0)
				codes[0] = EXC_UNIX_BAD_SYSCALL;
		case LINUX_SIGPIPE:
			mach_exception = EXC_SOFTWARE;
			if (codes[0] == 0)
				codes[0] = EXC_UNIX_BAD_PIPE;
		case LINUX_SIGABRT:
			mach_exception = EXC_SOFTWARE;
			if (codes[0] == 0)
				codes[0] = EXC_UNIX_ABORT;
		*/
		default:
			if (task->has_sigexc) {
				if (codes[0] == 0)
					codes[0] = EXC_SOFT_SIGNAL;
				codes[1] = bsd_signal_number;
				bsd_exception(EXC_SOFTWARE, codes, 2);
			} else {
				dtape_hooks->thread_set_pending_signal(thread->context, bsd_signal_number);
			}
			goto out;
	}

	dtape_log_debug("calling exception_triage_thread(%d, [%lld, %lld])", mach_exception, codes[0], codes[1]);

	exception_triage_thread(mach_exception, codes, EXCEPTION_CODE_MAX, &thread->xnu_thread);

	dtape_log_debug("exception_triage_thread returned");

out:
	thread->processing_signal = false;
};

extern int ux_exception(int exception, mach_exception_code_t code, mach_exception_subcode_t subcode);

kern_return_t handle_ux_exception(thread_t xthread, int exception, mach_exception_code_t code, mach_exception_subcode_t subcode) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	// translate exception and code to signal type
	int ux_signal = ux_exception(exception, code, subcode);

	if (thread->processing_signal) {
		dtape_hooks->thread_set_pending_signal(thread->context, ux_signal);
	} else {
		dtape_stub_unsafe("handle_ux_exception(): TODO: introduce signal into thread");
	}

	return KERN_SUCCESS;
};

void dtape_thread_wait_while_user_suspended(dtape_thread_t* thread) {
	if (&thread->xnu_thread != current_thread()) {
		panic("Cannot wait with non-current thread");
	}

	// TODO: we need to somehow detect when the thread has a signal pending.
	//
	//       we can check `/proc/<pid>/task/<tid>/status` and look at `SigPnd`,
	//       but this would require us checking periodically (i.e. polling).
	//       not terrible, but not ideal. additionally, we wouldn't do this for ALL threads,
	//       only threads currently blocked here, so it's not so bad.
	//
	//       we could also use SA_NODEFER and immediately have the process notify us.
	//       this requires a lot more work to implement properly, however.
	//       but, it does mean that we avoid polling.
	//
	//       another possible approach is to take advantage of a strange epoll and signalfd interaction described here: https://stackoverflow.com/a/29751604/6620880
	//       essentially, we send a thread our epoll descriptor along with some data (for us to identify the new context) and have it register a signalfd for itself.
	//       when the thread receives a signal, our epoll context will be notified.
	//       unfortunately, this has downsides either way it's done:
	//         1. we can register the signalfd at the start of each thread, which saves us the delay of doing it on every signal,
	//            but this means each thread will use yet another descriptor (in addition to their individual RPC sockets).
	//         2. we can register the signalfd only when we receive a signal, since we only need to check for pending signals during sigprocess,
	//            but this means signal processing incurs an additional delay.

	while (thread->xnu_thread.suspend_count > 0) {
		dtape_log_debug("sigexc: going to sleep");

		dtape_mutex_lock(&thread->suspension_mutex);
		thread->waiting_suspended = true;
		dtape_mutex_unlock(&thread->suspension_mutex);
		dtape_condvar_signal(&thread->suspension_condvar, SIZE_MAX);

		// FIXME: possible race condition here between notifying of waiting and actually sleeping

		thread->xnu_thread.wait_result = THREAD_WAITING;

		dtape_hooks->thread_suspend(thread->context, NULL, NULL, NULL);

		dtape_log_debug("sigexc: woken up");

		dtape_mutex_lock(&thread->suspension_mutex);
		thread->waiting_suspended = false;
		dtape_mutex_unlock(&thread->suspension_mutex);
		dtape_condvar_signal(&thread->suspension_condvar, SIZE_MAX);

		if (thread->xnu_thread.wait_result == THREAD_INTERRUPTED) {
			break;
		}
	}
};

void dtape_thread_retain(dtape_thread_t* thread) {
	thread_reference(&thread->xnu_thread);
};

void dtape_thread_release(dtape_thread_t* thread) {
	thread_deallocate(&thread->xnu_thread);
};

void dtape_thread_sigexc_enter(dtape_thread_t* thread) {
	thread_lock(&thread->xnu_thread);
	thread->xnu_thread.state &= ~(TH_UNINT | TH_WAIT);
	thread->xnu_thread.wait_result = THREAD_INTERRUPTED;
	clear_wait_internal(&thread->xnu_thread, THREAD_INTERRUPTED);
	thread_unlock(&thread->xnu_thread);
};

void dtape_thread_sigexc_enter2(dtape_thread_t* thread) {
	dtape_thread_user_state_t* new_user_state = malloc(sizeof(dtape_thread_user_state_t));
	if (!new_user_state) {
		panic("ran out of memory");
	}

	memset(new_user_state, 0, sizeof(*new_user_state));

	thread_lock(&thread->xnu_thread);
	LIST_INSERT_HEAD(&thread->user_states, new_user_state, link);
	thread_unlock(&thread->xnu_thread);
};

void dtape_thread_sigexc_exit(dtape_thread_t* thread) {
	dtape_thread_user_state_t* user_state = NULL;

	thread_lock(&thread->xnu_thread);
	user_state = LIST_FIRST(&thread->user_states);
	LIST_REMOVE(user_state, link);
	thread_unlock(&thread->xnu_thread);

	free(user_state);
};

void dtape_thread_dying(dtape_thread_t* thread) {
	thread_lock(&thread->xnu_thread);
	thread->xnu_thread.state &= ~(TH_UNINT | TH_WAIT);
	thread->xnu_thread.state |= TH_TERMINATE;
	thread->xnu_thread.wait_result = THREAD_INTERRUPTED;
	clear_wait_internal(&thread->xnu_thread, THREAD_INTERRUPTED);
	thread_unlock(&thread->xnu_thread);
};

thread_t current_thread(void) {
	dtape_thread_t* thread = dtape_hooks->current_thread();
	return thread ? &thread->xnu_thread : NULL;
};

void (thread_reference)(thread_t thread) {
	os_ref_retain(&thread->ref_count);
};

void thread_deallocate(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	if (os_ref_release(&xthread->ref_count) > 0) {
		return;
	}
	dtape_thread_destroy(thread);
};

void thread_deallocate_safe(thread_t thread) {
	return thread_deallocate(thread);
};

static void thread_continuation_callback(void* context) {
	dtape_thread_t* thread = context;
	thread_continue_t continuation;
	void* parameter;
	wait_result_t wait_result;

	thread_lock(&thread->xnu_thread);
	continuation = thread->xnu_thread.continuation;
	thread->xnu_thread.continuation = NULL;

	parameter = thread->xnu_thread.parameter;
	thread->xnu_thread.parameter = NULL;

	wait_result = thread->xnu_thread.wait_result;
	thread_unlock(&thread->xnu_thread);

	continuation(parameter, wait_result);

	thread_terminate_self();
};

wait_result_t thread_block_parameter(thread_continue_t continuation, void* parameter) {
	dtape_thread_t* thread = dtape_hooks->current_thread();

	thread_lock(&thread->xnu_thread);

	thread->xnu_thread.continuation = continuation;
	thread->xnu_thread.parameter = parameter;

	bool waiting = thread->xnu_thread.state & TH_WAIT;

	thread_unlock(&thread->xnu_thread);

	if (waiting) {
		dtape_hooks->thread_suspend(thread->context, continuation ? thread_continuation_callback : NULL, thread, NULL);
	}

	thread_lock(&thread->xnu_thread);
	wait_result_t wait_result = thread->xnu_thread.wait_result;
	thread_unlock(&thread->xnu_thread);

	if (continuation) {
		// TODO: we should add a thread hook to jump to a continuation without suspending
		continuation(parameter, wait_result);
		__builtin_unreachable();
	}

	return wait_result;
};

wait_result_t thread_block(thread_continue_t continuation) {
	return thread_block_parameter(continuation, NULL);
};

// thread locked
boolean_t thread_unblock(thread_t xthread, wait_result_t wresult) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	thread->xnu_thread.wait_result = wresult;
	dtape_hooks->thread_resume(thread->context);
	return TRUE;
};

// thread locked
kern_return_t thread_go(thread_t thread, wait_result_t wresult, waitq_options_t option) {
	return thread_unblock(thread, wresult) ? KERN_SUCCESS : KERN_FAILURE;
};

wait_result_t thread_mark_wait_locked(thread_t thread, wait_interrupt_t interruptible_orig) {
	dtape_stub_safe();
	thread->state = TH_WAIT;
	thread->wait_result = THREAD_WAITING;
	thread->block_hint = thread->pending_block_hint;
	thread->pending_block_hint = kThreadWaitNone;
	return THREAD_WAITING;
};

kern_return_t thread_terminate(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	dtape_hooks->thread_terminate(thread->context);
	return KERN_SUCCESS;
};

void thread_terminate_self(void) {
	thread_terminate(current_thread());
};

void thread_sched_call(thread_t thread, sched_call_t call) {
	thread->sched_call = call;
};

kern_return_t kernel_thread_create(thread_continue_t continuation, void* parameter, integer_t priority, thread_t* new_thread) {
	dtape_thread_t* thread = dtape_hooks->thread_create_kernel();
	if (!thread) {
		return KERN_FAILURE;
	}

	thread_reference(&thread->xnu_thread);
	*new_thread = &thread->xnu_thread;

	thread->xnu_thread.continuation = continuation;
	thread->xnu_thread.parameter = parameter;
	thread->xnu_thread.state = TH_WAIT | TH_UNINT;

	dtape_hooks->thread_setup(thread->context, thread_continuation_callback, thread);

	return KERN_SUCCESS;
};

void thread_set_thread_name(thread_t xthread, const char* name) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	thread->name = name;
};

__attribute__((noreturn))
void thread_syscall_return(kern_return_t ret) {
	dtape_hooks->current_thread_syscall_return(ret);
	__builtin_unreachable();
};

kern_return_t
thread_set_state(
    register thread_t       thread,
    int                     flavor,
    thread_state_t          state,
    mach_msg_type_number_t  state_count)
{
	dtape_thread_t* dthread = dtape_thread_for_xnu_thread(thread);
	dtape_task_t* dtask = dtape_task_for_thread(dthread);
	dtape_thread_user_state_t* user_state = LIST_FIRST(&dthread->user_states);

	if (dtask->architecture == dserver_rpc_architecture_x86_64 || dtask->architecture == dserver_rpc_architecture_i386) {
#if defined(__x86_64__) || defined(__i386__)
		switch (flavor)
		{
			case x86_THREAD_STATE:
			{
				x86_thread_state_t* s = (x86_thread_state_t*) state;

				if (state_count < x86_THREAD_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;

				if (s->tsh.flavor == x86_THREAD_STATE32)
				{
					if (dtask->architecture == dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->tsh.count;
					state = (thread_state_t) &s->uts.ts32;
				}
				else if (s->tsh.flavor == x86_THREAD_STATE64)
				{
					if (dtask->architecture != dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->tsh.count;
					state = (thread_state_t) &s->uts.ts64;
				}
				else
					return KERN_INVALID_ARGUMENT;

				flavor = s->tsh.flavor;
				break;
			}
			case x86_FLOAT_STATE:
			{
				x86_float_state_t* s = (x86_float_state_t*) state;

				if (state_count < x86_FLOAT_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;

				if (s->fsh.flavor == x86_FLOAT_STATE32)
				{
					if (dtask->architecture == dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->fsh.count;
					state = (thread_state_t) &s->ufs.fs32;
				}
				else if (s->fsh.flavor == x86_FLOAT_STATE64)
				{
					if (dtask->architecture != dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->fsh.count;
					state = (thread_state_t) &s->ufs.fs64;
				}
				else
					return KERN_INVALID_ARGUMENT;

				flavor = s->fsh.flavor;
				break;
			}
			case x86_DEBUG_STATE:
			{
				x86_debug_state_t* s = (x86_debug_state_t*) state;

				if (state_count < x86_DEBUG_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;

				if (s->dsh.flavor == x86_DEBUG_STATE32)
				{
					if (dtask->architecture == dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->dsh.count;
					state = (thread_state_t) &s->uds.ds32;
				}
				else if (s->dsh.flavor == x86_DEBUG_STATE64)
				{
					if (dtask->architecture != dserver_rpc_architecture_x86_64)
						return KERN_INVALID_ARGUMENT;

					state_count = s->dsh.count;
					state = (thread_state_t) &s->uds.ds64;
				}
				else
					return KERN_INVALID_ARGUMENT;

				flavor = s->dsh.flavor;
				break;
			}
		}

		switch (flavor)
		{
			case x86_THREAD_STATE32:
			{
				if (state_count < x86_THREAD_STATE32_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				const x86_thread_state32_t* s = (x86_thread_state32_t*) state;

				memcpy(&user_state->thread_state.uts.ts32, s, sizeof(*s));
				return KERN_SUCCESS;
			}
			case x86_THREAD_STATE64:
			{
				if (state_count < x86_THREAD_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture != dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				const x86_thread_state64_t* s = (x86_thread_state64_t*) state;

				// printf("Saving RIP 0x%lx, FLG 0x%lx\n", s->rip, s->rflags);

				memcpy(&user_state->thread_state.uts.ts64, s, sizeof(*s));
				return KERN_SUCCESS;
			}
			case x86_FLOAT_STATE32:
			{
				if (state_count < x86_FLOAT_STATE32_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				const x86_float_state32_t* s = (x86_float_state32_t*) state;

				memcpy(&user_state->float_state.ufs.fs32, s, sizeof(*s));
				return KERN_SUCCESS;
			}

			case x86_FLOAT_STATE64:
			{
				if (state_count < x86_FLOAT_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture != dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				const x86_float_state64_t* s = (x86_float_state64_t*) state;

				memcpy(&user_state->float_state.ufs.fs64, s, sizeof(*s));
				return KERN_SUCCESS;
			}
			case x86_DEBUG_STATE32:
			{
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;
				const x86_debug_state32_t* s = (x86_debug_state32_t*) state;
				x86_debug_state64_t s64;

				s64.dr0 = s->dr0;
				s64.dr1 = s->dr1;
				s64.dr2 = s->dr2;
				s64.dr3 = s->dr3;
				s64.dr4 = s->dr4;
				s64.dr5 = s->dr5;
				s64.dr6 = s->dr6;
				s64.dr7 = s->dr7;

				return thread_set_state(thread, x86_DEBUG_STATE64, (thread_state_t) &s,
						x86_DEBUG_STATE64_COUNT);
			}
			case x86_DEBUG_STATE64:
			{
#if 0
				if (dtask->architecture != dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				const x86_debug_state64_t* s = (x86_debug_state64_t*) state;

				struct thread_struct *lthread = &ltask->thread;
				int i;

				for (i = 0; i < 4; i++)
				{
					__uint64_t addr = (&s->dr0)[i];

					if (lthread->ptrace_bps[i] != NULL)
					{
						struct perf_event* pevent = lthread->ptrace_bps[i];
						struct perf_event_attr attr = pevent->attr;

						if (s->dr7 & (1 << (2*i)))
						{
							// Possibly modify an existing watchpoint
							fill_breakpoint(&attr, s->dr7, i);
							attr.bp_addr = addr;

							if (memcmp(&attr, &pevent->attr, sizeof(attr)) == 0)
								continue; // no change
						}
						else
						{
							// Disable the watchpoint
							if (attr.disabled)
								continue; // already disabled

							attr.disabled = true;
						}

						modify_user_hw_breakpoint(pevent, &attr);
					}
					else if (s->dr7 & (1 << (2*i)))
					{
						// Create a new watchpoint
						struct perf_event_attr attr;
						struct perf_event* pevent;

						fill_breakpoint(&attr, s->dr7, i);
						attr.bp_addr = addr;

						pevent = register_user_hw_breakpoint(&attr, watchpoint_callback, NULL, ltask);
						lthread->ptrace_bps[i] = pevent;
					}
				}

				return KERN_SUCCESS;
#else
				// TODO
				dtape_stub("debug state");
				return KERN_NOT_SUPPORTED;
#endif
			}
			default:
				return KERN_INVALID_ARGUMENT;
		}
#else
	__builtin_unreachable();
#endif
	} else if (dtask->architecture == dserver_rpc_architecture_arm64) {
#ifdef __aarch64__
		switch (flavor)
		{
			case ARM_THREAD_STATE64:
			{
				if (state_count < ARM_THREAD_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;

				const arm_thread_state64_t* s = (arm_thread_state64_t*) state;

				memcpy(&user_state->thread_state, s, sizeof(*s));
				return KERN_SUCCESS;
			}

			#warning "TODO: Implement other ARM64 user states"
			default:
				return KERN_INVALID_ARGUMENT;
		}
#else
	__builtin_unreachable();
#endif
	}
	return KERN_FAILURE;
}

kern_return_t
thread_get_state_internal(
    register thread_t       thread,
    int                     flavor,
    thread_state_t          state,          /* pointer to OUT array */
    mach_msg_type_number_t  *state_count,   /*IN/OUT*/
    boolean_t               to_user)
{
	dtape_thread_t* dthread = dtape_thread_for_xnu_thread(thread);
	dtape_task_t* dtask = dtape_task_for_thread(dthread);
	dtape_thread_user_state_t* user_state = LIST_FIRST(&dthread->user_states);

	// to_user is used to indicate whether to perform any necessary conversions from kernel to user thread state representations
	// it currently only does something on ARM64 when the authenticated pointers (`ptrauth_calls`) feature is enabled,
	// so i think it's safe to say we can ignore it in Darling (even when we get ARM support)

	if (dtask->architecture == dserver_rpc_architecture_x86_64 || dtask->architecture == dserver_rpc_architecture_i386) {
#if defined(__x86_64__) || defined(__i386__)
		switch (flavor)
		{
			// The following flavors automatically select 32 or 64-bit state
			// based on process type.
			case x86_THREAD_STATE:
			{
				x86_thread_state_t* s = (x86_thread_state_t*) state;

				if (*state_count < x86_THREAD_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
				{
					s->tsh.flavor = flavor = x86_THREAD_STATE64;
					s->tsh.count = x86_THREAD_STATE64_COUNT;
					state = (thread_state_t) &s->uts.ts64;
				}
				else
				{
					s->tsh.flavor = flavor = x86_THREAD_STATE32;
					s->tsh.count = x86_THREAD_STATE32_COUNT;
					state = (thread_state_t) &s->uts.ts32;
				}
				*state_count = x86_THREAD_STATE_COUNT;
				state_count = &s->tsh.count;

				break;
			}
			case x86_FLOAT_STATE:
			{
				x86_float_state_t* s = (x86_float_state_t*) state;

				if (*state_count < x86_FLOAT_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;

				if (dtask->architecture == dserver_rpc_architecture_x86_64)
				{
					s->fsh.flavor = flavor = x86_FLOAT_STATE64;
					s->fsh.count = x86_FLOAT_STATE64_COUNT;
					state = (thread_state_t) &s->ufs.fs64;
				}
				else
				{
					s->fsh.flavor = flavor = x86_FLOAT_STATE32;
					s->fsh.count = x86_FLOAT_STATE32_COUNT;
					state = (thread_state_t) &s->ufs.fs32;
				}
				*state_count = x86_FLOAT_STATE_COUNT;
				state_count = &s->fsh.count;
				break;
			}
			case x86_DEBUG_STATE:
			{
				x86_debug_state_t* s = (x86_debug_state_t*) state;

				if (*state_count < x86_DEBUG_STATE_COUNT)
					return KERN_INVALID_ARGUMENT;

				if (dtask->architecture == dserver_rpc_architecture_x86_64)
				{
					s->dsh.flavor = flavor = x86_DEBUG_STATE64;
					s->dsh.count = x86_DEBUG_STATE64_COUNT;
					state = (thread_state_t) &s->uds.ds64;
				}
				else
				{
					s->dsh.flavor = flavor = x86_DEBUG_STATE32;
					s->dsh.count = x86_DEBUG_STATE32_COUNT;
					state = (thread_state_t) &s->uds.ds32;
				}
				*state_count = x86_DEBUG_STATE_COUNT;
				state_count = &s->dsh.count;
				break;
			}
		}

		switch (flavor)
		{
			case x86_THREAD_STATE32:
			{
				if (*state_count < x86_THREAD_STATE32_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				x86_thread_state32_t* s = (x86_thread_state32_t*) state;

				*state_count = x86_THREAD_STATE32_COUNT;

				memcpy(s, &user_state->thread_state.uts.ts32, sizeof(*s));

				return KERN_SUCCESS;
			}
			case x86_FLOAT_STATE32:
			{
				if (*state_count < x86_FLOAT_STATE32_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				x86_float_state32_t* s = (x86_float_state32_t*) state;

				*state_count = x86_FLOAT_STATE32_COUNT;
				memcpy(s, &user_state->float_state.ufs.fs32, sizeof(*s));

				return KERN_SUCCESS;
			}
			case x86_FLOAT_STATE64: // these two are practically identical
			{
				if (*state_count < x86_FLOAT_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;

				x86_float_state64_t* s = (x86_float_state64_t*) state;

				*state_count = x86_FLOAT_STATE64_COUNT;
				memcpy(s, &user_state->float_state.ufs.fs64, sizeof(*s));

				return KERN_SUCCESS;
			}
			case x86_THREAD_STATE64:
			{
				if (*state_count < x86_THREAD_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture != dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				x86_thread_state64_t* s = (x86_thread_state64_t*) state;
				*state_count = x86_THREAD_STATE64_COUNT;

				memcpy(s, &user_state->thread_state.uts.ts64, sizeof(*s));

				// printf("Returning RIP 0x%x\n", s->rip);

				return KERN_SUCCESS;
			}
			case x86_DEBUG_STATE32:
			{
				if (*state_count < x86_DEBUG_STATE32_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture == dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				x86_debug_state32_t* s = (x86_debug_state32_t*) state;
				*state_count = x86_DEBUG_STATE32_COUNT;

				// Call self and translate from 64-bit
				x86_debug_state64_t s64;
				mach_msg_type_number_t count = x86_DEBUG_STATE64_COUNT;

				kern_return_t kr = thread_get_state_internal(thread, x86_DEBUG_STATE64,
						(thread_state_t) &s64, &count, FALSE);

				if (kr != KERN_SUCCESS)
					return kr;

				s->dr0 = s64.dr0;
				s->dr1 = s64.dr1;
				s->dr2 = s64.dr2;
				s->dr3 = s64.dr3;
				s->dr4 = s64.dr4;
				s->dr5 = s64.dr5;
				s->dr6 = s64.dr6;
				s->dr7 = s64.dr7;

				return KERN_SUCCESS;
			}
			case x86_DEBUG_STATE64:
			{
#if 0
				if (*state_count < x86_DEBUG_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;
				if (dtask->architecture != dserver_rpc_architecture_x86_64)
					return KERN_INVALID_ARGUMENT;

				x86_debug_state64_t* s = (x86_debug_state64_t*) state;
				*state_count = x86_DEBUG_STATE64_COUNT;

				memset(s, 0, sizeof(*s));

				struct thread_struct *lthread = &ltask->thread;
				int i;

				for (i = 0; i < 4; i++)
				{
					if (lthread->ptrace_bps[i] != NULL)
					{
						const struct perf_event_attr* attr = &lthread->ptrace_bps[i]->attr;

						if (!attr->disabled && attr->bp_type != HW_BREAKPOINT_EMPTY)
							s->dr7 |= 1 << (2*i); // set local enable flag

						switch (attr->bp_type)
						{
							case HW_BREAKPOINT_W:
								s->dr7 |= 1 << (16 + i*4);
								break;
							case HW_BREAKPOINT_RW:
							case HW_BREAKPOINT_R:
								s->dr7 |= 3 << (16 + i*4);
								break;
							case HW_BREAKPOINT_X:
								break;
						}

						switch (attr->bp_len)
						{
							case HW_BREAKPOINT_LEN_1:
								break;
							case HW_BREAKPOINT_LEN_2:
								s->dr7 |= 1 << (18 + i*4);
								break;
							case HW_BREAKPOINT_LEN_4:
								s->dr7 |= 3 << (18 + i*4);
								break;
							case HW_BREAKPOINT_LEN_8:
								s->dr7 |= 2 << (18 + i*4);
								break;
						}

						(&s->dr0)[i] = attr->bp_addr;
					}
				}

				return KERN_SUCCESS;
#else
				// TODO
				return KERN_NOT_SUPPORTED;
#endif
			}
			default:
				return KERN_INVALID_ARGUMENT;
		}
#else
		__builtin_unreachable();
#endif
	} else if (dtask->architecture == dserver_rpc_architecture_arm64) {
#ifdef __aarch64__
		switch (flavor)
		{
			case ARM_THREAD_STATE64:
			{
				if (*state_count < ARM_THREAD_STATE64_COUNT)
					return KERN_INVALID_ARGUMENT;

				arm_thread_state64_t* s = (arm_thread_state64_t*) state;
				*state_count = ARM_THREAD_STATE64_COUNT;

				memcpy(s, &user_state->thread_state, sizeof(*s));

				return KERN_SUCCESS;
			}
			
			#warning "TODO: Implement other ARM64 user states"
			default:
				return KERN_INVALID_ARGUMENT;
		}
#else
		__builtin_unreachable();
#endif
	} else {
		return KERN_FAILURE;
	}
}

kern_return_t
thread_get_state(
	thread_t                thread,
	int                     flavor,
	thread_state_t          state, /* pointer to OUT array */
	mach_msg_type_number_t  *state_count) /*IN/OUT*/
{
	return thread_get_state_internal(thread, flavor, state, state_count, FALSE);
}

thread_qos_t thread_get_requested_qos(thread_t thread, int* relpri) {
	dtape_stub_safe();
	*relpri = 0;
	return THREAD_QOS_DEFAULT;
};

thread_qos_t thread_user_promotion_qos_for_pri(int priority) {
	dtape_stub_safe();
	return THREAD_QOS_DEFAULT;
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
	thread->pending_block_hint = block_hint;
};

kern_return_t thread_set_state_from_user(thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t state_count) {
	return thread_set_state(thread, flavor, state, state_count);
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

void thread_poll_yield(thread_t self) {
	dtape_stub_safe();
};

kern_return_t act_get_state_to_user(thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t act_set_state_from_user(thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t count) {
	dtape_stub_unsafe();
};

kern_return_t thread_abort(thread_t thread) {
	dtape_stub_unsafe();
};

kern_return_t thread_abort_safely(thread_t thread) {
	// TODO: actually do something?
	//       in the LKM, we used to call `kick_process` here
	//       (which would presumably interrupt any syscalls).
	//       to replicate that, we'd probably have to use another
	//       real-time signal with SA_RESTART off.
	dtape_stub();
	return KERN_SUCCESS;
};

kern_return_t thread_convert_thread_state(thread_t thread, int direction, thread_state_flavor_t flavor, thread_state_t in_state, mach_msg_type_number_t in_state_count, thread_state_t out_state, mach_msg_type_number_t* out_state_count) {
	dtape_stub_unsafe();
};

kern_return_t thread_create_from_user(task_t task, thread_t* new_thread) {
	dtape_stub_unsafe();
};

kern_return_t thread_create_running_from_user(task_t task, int flavor, thread_state_t new_state, mach_msg_type_number_t new_state_count, thread_t* new_thread) {
	dtape_stub_unsafe();
};

kern_return_t thread_depress_abort_from_user(thread_t thread) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t thread_info(thread_t xthread, thread_flavor_t flavor, thread_info_t thread_info_out, mach_msg_type_number_t* thread_info_count) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	switch (flavor) {
		case THREAD_IDENTIFIER_INFO: {
			if (*thread_info_count < THREAD_IDENTIFIER_INFO_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
			*thread_info_count = THREAD_IDENTIFIER_INFO_COUNT;

			thread_identifier_info_t info = (thread_identifier_info_t)thread_info_out;

			thread_lock(xthread);

			info->thread_id = xthread->thread_id;
			info->thread_handle = thread->pthread_handle;
			info->dispatch_qaddr = thread->dispatch_qaddr;

			thread_unlock(xthread);

			return KERN_SUCCESS;
		};

		case THREAD_BASIC_INFO: {
			if (*thread_info_count < THREAD_BASIC_INFO_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
			*thread_info_count = THREAD_BASIC_INFO_COUNT;

			thread_basic_info_t info = (thread_basic_info_t) thread_info_out;
			dtape_thread_state_t thread_state = -1;

			thread_lock(xthread);

			// TODO: fill in these values properly
			info->cpu_usage = 0;
			info->flags = 0;
			info->policy = 0;
			info->sleep_time = 0;
			info->system_time.seconds = 0;
			info->system_time.microseconds = 0;
			info->user_time.seconds = 0;
			info->user_time.microseconds = 0;

			info->suspend_count = xthread->user_stop_count;

			thread_unlock(xthread);

			// check if the thread is currently waiting suspended; in that case, the `thread_get_state` hook will
			// report that it is waiting interruptibly (because that's what Linux sees), but we know that it's
			// actually "stopped" waiting for us to resume it.
			dtape_mutex_lock(&thread->suspension_mutex);
			if (thread->waiting_suspended) {
				thread_state = dtape_thread_state_stopped;
			}
			dtape_mutex_unlock(&thread->suspension_mutex);

			if (thread_state == -1) {
				thread_state = dtape_hooks->thread_get_state(thread->context);
			}

			switch (thread_state) {
				case dtape_thread_state_dead:
					info->run_state = 0;
					break;
				case dtape_thread_state_running:
					info->run_state = TH_STATE_RUNNING;
					break;
				case dtape_thread_state_stopped:
					info->run_state = TH_STATE_STOPPED;
					break;
				case dtape_thread_state_interruptible:
					info->run_state = TH_STATE_WAITING;
					break;
				case dtape_thread_state_uninterruptible:
					info->run_state = TH_STATE_UNINTERRUPTIBLE;
					break;
				default:
					panic("invalid thread state: %d; this should be impossible", thread_state);
			}

			return KERN_SUCCESS;
		};

		default:
			dtape_stub_unsafe("Unimplemented flavor");
	}
};

kern_return_t thread_policy(thread_t thread, policy_t policy, policy_base_t base, mach_msg_type_number_t count, boolean_t set_limit) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t thread_policy_get(thread_t thread, thread_policy_flavor_t flavor, thread_policy_t policy_info, mach_msg_type_number_t* count, boolean_t* get_default) {
	dtape_stub_unsafe();
};

kern_return_t thread_policy_set(thread_t thread, thread_policy_flavor_t flavor, thread_policy_t policy_info, mach_msg_type_number_t count) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t thread_set_mach_voucher(thread_t thread, ipc_voucher_t voucher) {
	dtape_stub_unsafe();
};

kern_return_t thread_set_policy(thread_t thread, processor_set_t pset, policy_t policy, policy_base_t base, mach_msg_type_number_t base_count, policy_limit_t limit, mach_msg_type_number_t limit_count) {
	dtape_stub_unsafe();
};

kern_return_t thread_wire(host_priv_t host_priv, thread_t thread, boolean_t wired) {
	dtape_stub_unsafe();
};

kern_return_t thread_getstatus_to_user(thread_t thread, int flavor, thread_state_t tstate, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t thread_setstatus_from_user(thread_t thread, int flavor, thread_state_t tstate, mach_msg_type_number_t count) {
	dtape_stub_unsafe();
};

boolean_t thread_should_abort(thread_t thread) {
	dtape_stub();
	return FALSE;
};

static wait_result_t thread_handoff_internal(thread_t thread, thread_continue_t continuation, void* parameter, thread_handoff_option_t option) {
	if (thread != THREAD_NULL) {
		if (continuation == NULL || (option & THREAD_HANDOFF_SETRUN_NEEDED)) {
			thread_deallocate_safe(thread);
		}

		// in the real thread_handoff_internal(), an attempt is made to grab the thread to handoff to.
		// if it could not be pulled from its runq, the current thread simply blocks with thread_block_parameter().
		// therefore, it's not necessary to actually handoff to the given thread, so we don't do that, in order to make our implementation easier.
	}

	return thread_block_parameter(continuation, parameter);
};

void thread_hold(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	dtape_log_debug("sigexc: thread_hold(%p)\n", xthread);
	// CHECKME: the LKM was always sending the signal whenever thread_hold got called;
	//          we mimic XNU here instead. check whether this actually works as expected.
	if (xthread->suspend_count++ == 0) {
		// This signal leads to sigexc.c which will end up calling darlingserver;
		// darlingserver will hold the caller so long as the suspend_count > 0.
		dtape_hooks->thread_send_signal(thread->context, LINUX_SIGRTMIN);
	}
};

void thread_release(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	dtape_log_debug("sigexc: thread_release(%p)\n", xthread);
	xthread->suspend_count--;
	dtape_hooks->thread_resume(thread->context);
};

void thread_wait(thread_t xthread, boolean_t until_not_runnable) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	dtape_mutex_lock(&thread->suspension_mutex);
	while (!thread->waiting_suspended) {
		dtape_condvar_wait(&thread->suspension_condvar, &thread->suspension_mutex);
	}
	dtape_mutex_unlock(&thread->suspension_mutex);
};

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

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	void                    *p0,
	__unused void   *p1)
{
	thread_t                thread = p0;
	spl_t                   s;

	assert_thread_magic(thread);

	s = splsched();
	thread_lock(thread);
	if (--thread->wait_timer_active == 0) {
		if (thread->wait_timer_is_set) {
			thread->wait_timer_is_set = FALSE;
			clear_wait_internal(thread, THREAD_TIMED_OUT);
		}
	}
	thread_unlock(thread);
	splx(s);
}

/*
 *	assert_wait_queue:
 *
 *	Return the global waitq for the specified event
 */
struct waitq *
assert_wait_queue(
	event_t                         event)
{
	return global_eventq(event);
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/kern/thread.c">

kern_return_t
thread_assign(
	__unused thread_t                       thread,
	__unused processor_set_t        new_pset)
{
	return KERN_FAILURE;
}

/*
 *	thread_assign_default:
 *
 *	Special version of thread_assign for assigning threads to default
 *	processor set.
 */
kern_return_t
thread_assign_default(
	thread_t                thread)
{
	return thread_assign(thread, &pset0);
}

/*
 *	thread_get_assignment
 *
 *	Return current assignment for this thread.
 */
kern_return_t
thread_get_assignment(
	thread_t                thread,
	processor_set_t *pset)
{
	if (thread == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	*pset = &pset0;

	return KERN_SUCCESS;
}

/*
 *  thread_get_mach_voucher - return a voucher reference for the specified thread voucher
 *
 *  Conditions:  nothing locked
 *
 *  NOTE:       At the moment, there is no distinction between the current and effective
 *		vouchers because we only set them at the thread level currently.
 */
kern_return_t
thread_get_mach_voucher(
	thread_act_t            thread,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t           *voucherp)
{
	ipc_voucher_t           voucher;

	if (THREAD_NULL == thread) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);
	voucher = thread->ith_voucher;

	if (IPC_VOUCHER_NULL != voucher) {
		ipc_voucher_reference(voucher);
		thread_mtx_unlock(thread);
		*voucherp = voucher;
		return KERN_SUCCESS;
	}

	thread_mtx_unlock(thread);

	*voucherp = IPC_VOUCHER_NULL;
	return KERN_SUCCESS;
}

/*
 *  thread_swap_mach_voucher - swap a voucher reference for the specified thread voucher
 *
 *  Conditions: callers holds a reference on the new and presumed old voucher(s).
 *		nothing locked.
 *
 *  This function is no longer supported.
 */
kern_return_t
thread_swap_mach_voucher(
	__unused thread_t               thread,
	__unused ipc_voucher_t          new_voucher,
	ipc_voucher_t                   *in_out_old_voucher)
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

kern_return_t
kernel_thread_start_priority(
	thread_continue_t       continuation,
	void                            *parameter,
	integer_t                       priority,
	thread_t                        *new_thread)
{
	kern_return_t   result;
	thread_t                thread;

	result = kernel_thread_create(continuation, parameter, priority, &thread);
	if (result != KERN_SUCCESS) {
		return result;
	}

	*new_thread = thread;

	thread_mtx_lock(thread);
	thread_start(thread);
	thread_mtx_unlock(thread);

	return result;
}

kern_return_t
kernel_thread_start(
	thread_continue_t       continuation,
	void                            *parameter,
	thread_t                        *new_thread)
{
	return kernel_thread_start_priority(continuation, parameter, -1, new_thread);
}

uint64_t
thread_tid(
	thread_t        thread)
{
	return thread != THREAD_NULL? thread->thread_id: 0;
}

/*
 *	thread_read_deallocate:
 *
 *	Drop a reference on thread read port.
 */
void
thread_read_deallocate(
	thread_read_t                thread_read)
{
	return thread_deallocate((thread_t)thread_read);
}

/*
 *	thread_inspect_deallocate:
 *
 *	Drop a thread inspection reference.
 */
void
thread_inspect_deallocate(
	thread_inspect_t                thread_inspect)
{
	return thread_deallocate((thread_t)thread_inspect);
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/kern/syscall_subr.c">

void
thread_handoff_parameter(thread_t thread, thread_continue_t continuation,
    void *parameter, thread_handoff_option_t option)
{
	thread_handoff_internal(thread, continuation, parameter, option);
	panic("NULL continuation passed to %s", __func__);
	__builtin_unreachable();
}

wait_result_t
thread_handoff_deallocate(thread_t thread, thread_handoff_option_t option)
{
	return thread_handoff_internal(thread, NULL, NULL, option);
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/kern/thread_act.c">

/*
 * Internal routine to mark a thread as waiting
 * right after it has been created.  The caller
 * is responsible to call wakeup()/thread_wakeup()
 * or thread_terminate() to get it going.
 *
 * Always called with the thread mutex locked.
 *
 * Task and task_threads mutexes also held
 * (so nobody can set the thread running before
 * this point)
 *
 * Converts TH_UNINT wait to THREAD_INTERRUPTIBLE
 * to allow termination from this point forward.
 */
void
thread_start_in_assert_wait(
	thread_t                        thread,
	event_t             event,
	wait_interrupt_t    interruptible)
{
	struct waitq *waitq = assert_wait_queue(event);
	wait_result_t wait_result;
	spl_t spl;

	spl = splsched();
	waitq_lock(waitq);

	/* clear out startup condition (safe because thread not started yet) */
	thread_lock(thread);
	assert(!thread->started);
	assert((thread->state & (TH_WAIT | TH_UNINT)) == (TH_WAIT | TH_UNINT));
	thread->state &= ~(TH_WAIT | TH_UNINT);
	thread_unlock(thread);

	/* assert wait interruptibly forever */
	wait_result = waitq_assert_wait64_locked(waitq, CAST_EVENT64_T(event),
	    interruptible,
	    TIMEOUT_URGENCY_SYS_NORMAL,
	    TIMEOUT_WAIT_FOREVER,
	    TIMEOUT_NO_LEEWAY,
	    thread);
	assert(wait_result == THREAD_WAITING);

	/* mark thread started while we still hold the waitq lock */
	thread_lock(thread);
	thread->started = TRUE;
	thread_unlock(thread);

	waitq_unlock(waitq);
	splx(spl);
}

void
thread_start(
	thread_t                        thread)
{
	clear_wait(thread, THREAD_AWAKENED);
	thread->started = TRUE;
}

kern_return_t
thread_get_state_to_user(
	thread_t                thread,
	int                                             flavor,
	thread_state_t                  state,                  /* pointer to OUT array */
	mach_msg_type_number_t  *state_count)   /*IN/OUT*/
{
	return thread_get_state_internal(thread, flavor, state, state_count, TRUE);
}

kern_return_t
thread_suspend(thread_t thread)
{
	kern_return_t result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread->user_stop_count++ == 0) {
			thread_hold(thread);
		}
	} else {
		result = KERN_TERMINATED;
	}

	thread_mtx_unlock(thread);

	if (thread != current_thread() && result == KERN_SUCCESS) {
		thread_wait(thread, FALSE);
	}

	return result;
}

kern_return_t
thread_resume(thread_t thread)
{
	kern_return_t result = KERN_SUCCESS;

	if (thread == THREAD_NULL || thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);

	if (thread->active) {
		if (thread->user_stop_count > 0) {
			if (--thread->user_stop_count == 0) {
				thread_release(thread);
			}
		} else {
			result = KERN_FAILURE;
		}
	} else {
		result = KERN_TERMINATED;
	}

	thread_mtx_unlock(thread);

	return result;
}

// </copied>

// <copied from="xnu://7195.141.2/bsd/uxkern/ux_exception.c">

/*
 * Translate Mach exceptions to UNIX signals.
 *
 * ux_exception translates a mach exception, code and subcode to
 * a signal.  Calls machine_exception (machine dependent)
 * to attempt translation first.
 */
#ifdef __DARLING__
int
#else
static int
#endif
ux_exception(int                        exception,
    mach_exception_code_t      code,
    mach_exception_subcode_t   subcode)
{
	int machine_signal = 0;

#ifndef __DARLING__
	/* Try machine-dependent translation first. */
	if ((machine_signal = machine_exception(exception, code, subcode)) != 0) {
		return machine_signal;
	}
#endif

	switch (exception) {
	case EXC_BAD_ACCESS:
		if (code == KERN_INVALID_ADDRESS) {
			return SIGSEGV;
		} else {
			return SIGBUS;
		}

	case EXC_BAD_INSTRUCTION:
		return SIGILL;

	case EXC_ARITHMETIC:
		return SIGFPE;

#ifndef __DARLING__
	case EXC_EMULATION:
		return SIGEMT;
#endif

	case EXC_SOFTWARE:
		switch (code) {
		case EXC_UNIX_BAD_SYSCALL:
			return SIGSYS;
		case EXC_UNIX_BAD_PIPE:
			return SIGPIPE;
		case EXC_UNIX_ABORT:
			return SIGABRT;
		case EXC_SOFT_SIGNAL:
			return SIGKILL;
		}
		break;

	case EXC_BREAKPOINT:
		return SIGTRAP;
	}

	return 0;
}

// </copied>
