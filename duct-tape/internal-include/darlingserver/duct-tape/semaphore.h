#ifndef _DARLINGSERVER_DUCT_TAPE_SEMAPHORE_H_
#define _DARLINGSERVER_DUCT_TAPE_SEMAPHORE_H_

#include <darlingserver/duct-tape.h>

#include <kern/sync_sema.h>

struct dtape_semaphore {
	dtape_task_t* owning_task;
	semaphore_t xnu_semaphore;
};

#endif // _DARLINGSERVER_DUCT_TAPE_SEMAPHORE_H_
