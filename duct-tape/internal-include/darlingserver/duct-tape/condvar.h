#ifndef _DARLINGSERVER_DUCT_TAPE_CONDVAR_H_
#define _DARLINGSERVER_DUCT_TAPE_CONDVAR_H_

#include "locks.h"

typedef struct dtape_condvar {
	libsimple_lock_t queue_lock;
	dtape_mutex_head_t queue_head;
} dtape_condvar_t;

void dtape_condvar_init(dtape_condvar_t* condvar);
void dtape_condvar_signal(dtape_condvar_t* condvar, size_t count);
void dtape_condvar_wait(dtape_condvar_t* condvar, dtape_mutex_t* mutex);

#endif // _DARLINGSERVER_DUCT_TAPE_CONDVAR_H_
