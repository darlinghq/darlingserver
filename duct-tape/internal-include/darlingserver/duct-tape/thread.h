#ifndef _DARLINGSERVER_DUCT_TAPE_THREAD_H_
#define _DARLINGSERVER_DUCT_TAPE_THREAD_H_

#include <kern/thread.h>
#include <darlingserver/duct-tape/locks.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/condvar.h>

#include <sys/event.h>

typedef struct dtape_thread dtape_thread_t;

struct dtape_opaque_ksyn_waitq_element {
	// more than enough for the actual structure (should be a max of 56 bytes)
	char opaque[64];
};

typedef struct dtape_thread_user_state {
	LIST_ENTRY(dtape_thread_user_state) link;

#if __x86_64__
	x86_thread_state_t thread_state;
	x86_float_state_t float_state;
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

	bool waiting_suspended;
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

#endif // _DARLINGSERVER_DUCT_TAPE_THREAD_H_
