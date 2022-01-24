#ifndef _DARLINGSERVER_DUCT_TAPE_THREAD_H_
#define _DARLINGSERVER_DUCT_TAPE_THREAD_H_

#include <kern/thread.h>
#include <darlingserver/duct-tape/locks.h>

typedef struct dtape_thread {
	void* context;
	dtape_mutex_link_t mutex_link;
	const char* name;
	uintptr_t pthread_handle;
	uintptr_t dispatch_qaddr;
	struct thread xnu_thread;
} dtape_thread_t;

__attribute__((always_inline))
static dtape_thread_t* dtape_thread_for_xnu_thread(thread_t xnu_thread) {
	return (dtape_thread_t*)((char*)xnu_thread - offsetof(dtape_thread_t, xnu_thread));
};

#endif // _DARLINGSERVER_DUCT_TAPE_THREAD_H_
