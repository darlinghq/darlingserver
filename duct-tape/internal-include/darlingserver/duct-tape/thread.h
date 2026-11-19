#ifndef _DARLINGSERVER_DUCT_TAPE_THREAD_H_
#define _DARLINGSERVER_DUCT_TAPE_THREAD_H_

#include <kern/thread.h>
#include <darlingserver/duct-tape/locks.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/condvar.h>

#include <sys/event.h>

typedef struct dtape_thread dtape_thread_t;

struct dtape_reserved_region {
	// the kernel-side object the region is for: an out-of-line memory copy or an out-of-line port array
	const void* key;
	uintptr_t address;
	size_t size;
};

struct dtape_opaque_ksyn_waitq_element {
	// more than enough for the actual structure (should be a max of 56 bytes)
	char opaque[64];
};

typedef struct dtape_thread_user_state {
	LIST_ENTRY(dtape_thread_user_state) link;

#if __x86_64__
	x86_thread_state_t thread_state;
	x86_float_state_t float_state;
#elif __aarch64__
	arm_unified_thread_state_t thread_state;
	arm_neon_state64_t float_state;
#endif
} dtape_thread_user_state_t;

typedef LIST_HEAD(dtape_thread_user_state_head, dtape_thread_user_state) dtape_thread_user_state_head_t;

struct dtape_thread {
	void* context;
	dtape_mutex_link_t mutex_link;
	const char* name;
	uintptr_t pthread_handle;
	uintptr_t dispatch_qaddr;
	struct kevent_ctx_s kevent_ctx;
	dtape_thread_user_state_head_t user_states;
	dtape_thread_user_state_t default_state;
	bool processing_signal;

	// a mach_msg send to a kernel object that fails only because a server-to-client call it needed was interrupted
	// is handed back to the sender to be restarted (see ipc_kobject_server()).
	// set by mach_msg_overwrite_trap() around its send and consumed by the first ipc_kobject_server() call
	bool kobject_restart_allowed;
	// set by ipc_kobject_server() when it handed the request back instead of performing it
	bool kobject_restart_requested;
	// the object of a memory entry whose creation failed after its memory may have been mapped into the task;
	// kept until the thread's next mach_msg send completes, so a restarted request finds it (see mach_make_memory_entry_internal())
	struct dtape_map_shared_descriptor* kept_descriptor;

	// the out-of-line regions of the message this thread is receiving, mapped into its task before the message's
	// copyout starts (see dtape_kmsg_reserve_out_of_line()) and taken by the copyout instead of mapping new ones
	struct dtape_reserved_region* reserved_regions;
	size_t reserved_region_count;
	// set by mach_msg_overwrite_trap() for a receive-only call; consumed by mach_msg_receive_results(),
	// which may then have the call restarted (see there)
	bool receive_restart_allowed;
	// a message this thread had already dequeued when mapping its out-of-line memory was interrupted by a signal.
	// the restarted receive on the same port or port set (`pending_receive_object`, referenced) gets it
	struct ipc_kmsg* pending_receive_kmsg;
	struct ipc_object* pending_receive_object;
	mach_port_seqno_t pending_receive_seqno;

	bool waiting_suspended;
	// set (with the thread locked) when thread_unblock() ends a wait, cleared once the woken thread has picked up its
	// wait result. while it is set, the wait has already been completed (e.g. a receive has been handed its message)
	// and must not be turned into an interruption; see dtape_thread_sigexc_enter()
	bool wakeup_pending;
	// set when a signal arrived while `wakeup_pending` was set: the woken call runs on, but the next interruptible wait
	// it starts before it returns is interrupted at once. cleared then, or once the interrupted call is done
	// (dtape_thread_sigexc_enter2())
	bool interrupt_deferred;
	// held from the TH_WAIT check in thread_block_parameter() until the
	// microthread has been suspended; see thread_block_parameter()
	libsimple_lock_t block_suspend_gate;
	dtape_mutex_t suspension_mutex;
	dtape_condvar_t suspension_condvar;

	//
	// uthread stuff for psynch
	//
	struct dtape_opaque_ksyn_waitq_element kwe;
	lck_mtx_t  *uu_mtx;
	uint16_t uu_pri;
	caddr_t uu_wchan;
	int (*uu_continuation)(int);
	const char* uu_wmesg;
	int uu_flag;

	struct thread xnu_thread;
};

__attribute__((always_inline))
static dtape_thread_t* dtape_thread_for_xnu_thread(thread_t xnu_thread) {
	if (!xnu_thread) {
		return NULL;
	}
	return (dtape_thread_t*)((char*)xnu_thread - offsetof(dtape_thread_t, xnu_thread));
};

__attribute__((always_inline))
static dtape_task_t* dtape_task_for_thread(dtape_thread_t* thread) {
	if (!thread) {
		return NULL;
	}
	return dtape_task_for_xnu_task(thread->xnu_thread.task);
};

// gives up the message held for a restarted receive (if any) of a thread that is going away
void dtape_thread_abandon_pending_receive(dtape_thread_t* thread);

#endif // _DARLINGSERVER_DUCT_TAPE_THREAD_H_
