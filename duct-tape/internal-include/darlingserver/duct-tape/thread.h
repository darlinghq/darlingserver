#ifndef _DARLINGSERVER_DUCT_TAPE_THREAD_H_
#define _DARLINGSERVER_DUCT_TAPE_THREAD_H_

#include <kern/thread.h>
#include <darlingserver/duct-tape/locks.h>
#include <darlingserver/duct-tape/task.h>

#include <sys/event.h>

typedef struct dtape_thread dtape_thread_t;

struct dtape_thread {
	void* context;
	dtape_mutex_link_t mutex_link;
	const char* name;
	uintptr_t pthread_handle;
	uintptr_t dispatch_qaddr;
	struct kevent_ctx_s kevent_ctx;
#if __x86_64__
	x86_thread_state_t thread_state;
	x86_float_state_t float_state;
#endif
	struct thread xnu_thread;
};

__attribute__((always_inline))
static dtape_thread_t* dtape_thread_for_xnu_thread(thread_t xnu_thread) {
	return (dtape_thread_t*)((char*)xnu_thread - offsetof(dtape_thread_t, xnu_thread));
};

__attribute__((always_inline))
static dtape_task_t* dtape_task_for_thread(dtape_thread_t* thread) {
	return dtape_task_for_xnu_task(thread->xnu_thread.task);
};

#endif // _DARLINGSERVER_DUCT_TAPE_THREAD_H_
