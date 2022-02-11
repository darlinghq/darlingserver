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

	if (semaphore_create(&semaphore->owning_task->xnu_task, &semaphore->xnu_semaphore, 0, initial_value) != KERN_SUCCESS) {
		free(semaphore);
		return NULL;
	}

	return semaphore;
};

void dtape_semaphore_destroy(dtape_semaphore_t* semaphore) {
	if (semaphore_destroy(&semaphore->owning_task->xnu_task, semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to destroy duct-taped XNU semaphore");
	}
};

void dtape_semaphore_up(dtape_semaphore_t* semaphore) {
	if (semaphore_signal(semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to raise up-count of duct-taped XNU semaphore");
	}
};

void dtape_semaphore_down(dtape_semaphore_t* semaphore) {
	if (semaphore_wait(semaphore->xnu_semaphore) != KERN_SUCCESS) {
		panic("Failed to lower up-count of duct-taped XNU semaphore");
	}
};
