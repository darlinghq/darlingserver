#ifndef _DARLINGSERVER_DUCT_TAPE_TASK_H_
#define _DARLINGSERVER_DUCT_TAPE_TASK_H_

#include <kern/task.h>

typedef struct dtape_task {
	void* context;
	uint32_t saved_pid;

	struct task xnu_task;
} dtape_task_t;

__attribute__((always_inline))
static dtape_task_t* dtape_task_for_xnu_task(task_t xnu_task) {
	return (dtape_task_t*)((char*)xnu_task - offsetof(dtape_task_t, xnu_task));
};

#endif // _DARLINGSERVER_DUCT_TAPE_TASK_H_
