#include <darlingserver/duct-tape/semaphore.h>
#include <darlingserver/duct-tape/task.h>

#include <mach/semaphore.h>
#include <mach/task.h>

#include <stdlib.h>

dtape_semaphore_t* dtape_semaphore_create(dtape_task_t* owning_task, int initial_value) {
	dtape_semaphore_t* semaphore = malloc(sizeof(dtape_semaphore_t));
	if (!semaphore) {
		return NULL;
	}

	semaphore->owning_task = owning_task;
	semaphore->references = 1;

	if (semaphore_create(&semaphore->owning_task->xnu_task, &semaphore->xnu_semaphore, 0, initial_value) != KERN_SUCCESS) {
		free(semaphore);
		return NULL;
	}

	return semaphore;
};

// reference-counted, so a retained semaphore outlives its destroy
static void dtape_semaphore_put(dtape_semaphore_t* semaphore) {
	if (__atomic_sub_fetch(&semaphore->references, 1, __ATOMIC_ACQ_REL) == 0) {
		free(semaphore);
	}
};

void dtape_semaphore_destroy(dtape_semaphore_t* semaphore) {
	// wakes its waiters (KERN_TERMINATED) and drops the creator's XNU reference
	if (semaphore_destroy(&semaphore->owning_task->xnu_task, semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to destroy duct-taped XNU semaphore");
	}

	dtape_semaphore_put(semaphore);
};

void dtape_semaphore_retain(dtape_semaphore_t* semaphore) {
	semaphore_reference(semaphore->xnu_semaphore);
	__atomic_add_fetch(&semaphore->references, 1, __ATOMIC_RELAXED);
};

void dtape_semaphore_release(dtape_semaphore_t* semaphore) {
	semaphore_dereference(semaphore->xnu_semaphore);
	dtape_semaphore_put(semaphore);
};

void dtape_semaphore_up(dtape_semaphore_t* semaphore) {
	// one destroyed while a user still held a reference has no one to wake (XNU's
	// semaphore_signal() answers KERN_TERMINATED)
	kern_return_t kr = semaphore_signal(semaphore->xnu_semaphore);
	if (kr != KERN_SUCCESS && kr != KERN_TERMINATED) {
		panic("Failed to raise up-count of duct-taped XNU semaphore");
	}
};

dtape_semaphore_wait_result_t dtape_semaphore_down(dtape_semaphore_t* semaphore) {
	kern_return_t kr = semaphore_wait(semaphore->xnu_semaphore);
	switch (kr) {
		case KERN_SUCCESS:
			return dtape_semaphore_wait_result_ok;
		case KERN_ABORTED:
			return dtape_semaphore_wait_result_interrupted;
		default:
			return dtape_semaphore_wait_result_error;
	}
};

bool dtape_semaphore_down_simple(dtape_semaphore_t* semaphore) {
	kern_return_t kr = semaphore_wait(semaphore->xnu_semaphore);
	switch (kr) {
		case KERN_SUCCESS:
			return true;
		case KERN_ABORTED:
		// destroyed while retained; like an interruption, the wait is over
		case KERN_TERMINATED:
			return false;
		default:
			panic("Failed to lower up-count of duct-taped XNU semaphore: %d", kr);
	}
};
