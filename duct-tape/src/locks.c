#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/locks.h>
#include <kern/waitq.h>
#include <kern/thread.h>

#include <stdlib.h>

//
// mutex
//
// we can't use a waitq for this because waitqs themselves need to use locks.
//

// now you might be asking yourself:
// "why in the world would you have a queue for microthreads to wait if you already have a lock for the queue?"
// the reason is that that lock is a Linux futex-based lock. it will put the entire thread to sleep.
// however, we only want to suspend the microthread so that the thread itself is free to work with other microthreads
// while that microthread is waiting for the lock.
//
// therefore, we use the "actual" lock to control access to the queue and have a very brief critical section for the "actual" thread.
//
// as mentioned earlier, we want to be able to process other microthreads on "actual" threads while the current microthread
// waits for a lock. however, if that wasn't the case, we could use an "actual" lock if we knew for certain that none of the XNU code
// sleeps while holding a lock. however, that's simply not the case, and having to check for each possible case where locks are used in the relevant
// code would not be worth the effort. as for why sleeping a microthread while holding the lock would be undesirable in the case of an "actual" lock,
// it would mean that a deadlock could occur if the microthread holding the lock were "switched" out and all the microthreads that run after it want
// to acquire that lock (and then the microthread holding the lock would never get a chance to run and unlock it).
//
// also note that we need to hold the actual lock until the microthread is fully suspended.
// that's why the thread_suspend hook has an optional `libsimple_lock_t*` parameter.
// the hook is supposed to unlock the lock passed in for that argument once the microthread is fully suspended.
// this way, we can be certain that we won't miss any wakeups (from someone trying to resume us just after we add ourselves to the queue but before we suspend).

void dtape_mutex_init(dtape_mutex_t* mutex) {
	mutex->dtape_owner = 0;
	libsimple_lock_init(&mutex->dtape_queue_lock);
	TAILQ_INIT(&mutex->dtape_queue_head);
};

void dtape_mutex_assert(dtape_mutex_t* mutex, bool should_be_owned) {
	bool owned = mutex->dtape_owner == (uintptr_t)current_thread();

	if (should_be_owned && !owned) {
		panic("Lock assertion failed (not owned but expected to be owned)");
	} else if (!should_be_owned && owned) {
		panic("Lock assertion failed (owned but expected not to be owned)");
	}
};

void dtape_mutex_lock(dtape_mutex_t* mutex) {
	thread_t xthread = current_thread();
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	if (!thread) {
		dtape_log_warning("Trying to lock mutex without an active thread!");
		// if we don't have an active thread, we fall back to using the queue lock (which is a native lock).
		// note that this means that any microthreads that want to lock the lock will sleep for real!
		// therefore, callers that try to do this must only lock the lock for short periods
		while (true) {
			// FIXME: we really should be using a condvar here; right now, we're just spinning until the owner drops the lock.
			//        we'd need to implement condvars in libsimple first, though.
			libsimple_lock_lock(&mutex->dtape_queue_lock);
			if (mutex->dtape_owner == 0) {
				return;
			}
			libsimple_lock_unlock(&mutex->dtape_queue_lock);
			__builtin_ia32_pause();
		}
	}

	dtape_mutex_assert(mutex, false);

	while (true) {
		libsimple_lock_lock(&mutex->dtape_queue_lock);

		if (mutex->dtape_owner == 0 || mutex->dtape_owner == (uintptr_t)xthread) {
			// lock successfully acquired
			mutex->dtape_owner = (uintptr_t)xthread;
			libsimple_lock_unlock(&mutex->dtape_queue_lock);
			__atomic_thread_fence(__ATOMIC_ACQUIRE);
			return;
		}

		// lock not acquired; let's wait
		TAILQ_INSERT_TAIL(&mutex->dtape_queue_head, &thread->mutex_link, link);

		// this call drops the lock
		dtape_hooks->thread_suspend(thread->context, NULL, NULL, &mutex->dtape_queue_lock);
	}
};

bool dtape_mutex_try_lock(dtape_mutex_t* mutex) {
	thread_t xthread = current_thread();
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	if (!thread) {
		dtape_log_warning("Trying to lock mutex without an active thread!");
		// see lck_mtx_lock()
		if (libsimple_lock_try_lock(&mutex->dtape_queue_lock)) {
			if (mutex->dtape_owner == 0) {
				return TRUE;
			}
			libsimple_lock_unlock(&mutex->dtape_queue_lock);
		}
		return FALSE;
	}

	dtape_mutex_assert(mutex, false);

	if (mutex->dtape_owner == 0 || mutex->dtape_owner == (uintptr_t)xthread) {
		// lock successfully acquired
		mutex->dtape_owner = (uintptr_t)xthread;
		libsimple_lock_unlock(&mutex->dtape_queue_lock);
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		return TRUE;
	}

	// lock not acquired
	return FALSE;
};

void dtape_mutex_unlock(dtape_mutex_t* mutex) {
	thread_t xcurr_thread = current_thread();
	dtape_thread_t* curr_thread = dtape_thread_for_xnu_thread(xcurr_thread);

	if (!curr_thread) {
		dtape_log_warning("Trying to unlock mutex without an active thread!");
		// see lck_mtx_lock()
		return libsimple_lock_unlock(&mutex->dtape_queue_lock);
	}

	dtape_mutex_assert(mutex, true);

	libsimple_lock_lock(&mutex->dtape_queue_lock);
	mutex->dtape_owner = 0;

	dtape_mutex_link_t* link = TAILQ_FIRST(&mutex->dtape_queue_head);

	if (!link) {
		// uncontended case
		// no one is waiting for the lock, so we don't need to wake anyone up.
		goto out;
	}

	// contended case
	// one or more microthreads are waiting; wake the oldest waiter (the one at the head of queue).
	TAILQ_REMOVE(&mutex->dtape_queue_head, link, link);
	dtape_thread_t* thread = __container_of(link, dtape_thread_t, mutex_link);
	dtape_hooks->thread_resume(thread->context);

out:
	libsimple_lock_unlock(&mutex->dtape_queue_lock);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	return;
};

void lck_mtx_init(lck_mtx_t* lock, lck_grp_t* grp, lck_attr_t* attr) {
	lock->dtape_mutex = malloc(sizeof(dtape_mutex_t));
	if (!lock->dtape_mutex) {
		panic("Insufficient memory to allocate mutex");
	}
	dtape_mutex_init(lock->dtape_mutex);
};

void lck_mtx_destroy(lck_mtx_t* lock, lck_grp_t* grp) {
	if (lock->dtape_mutex->dtape_owner != 0) {
		panic("Attempt to destroy lock while being held");
	}

	free(lock->dtape_mutex);
	lock->dtape_mutex = NULL;
};

void lck_mtx_assert(lck_mtx_t* lock, unsigned int type) {
	dtape_mutex_assert(lock->dtape_mutex, type == LCK_ASSERT_OWNED);
};

void lck_mtx_lock(lck_mtx_t* lock) {
	dtape_mutex_lock(lock->dtape_mutex);
};

boolean_t lck_mtx_try_lock(lck_mtx_t* lock) {
	return dtape_mutex_try_lock(lock->dtape_mutex);
};

void lck_mtx_lock_spin_always(lck_mtx_t* lock) {
	lck_mtx_lock(lock);
};

void lck_mtx_lock_spin(lck_mtx_t* lock) {
	lck_mtx_lock(lock);
};

void lck_mtx_unlock(lck_mtx_t* lock) {
	dtape_mutex_unlock(lock->dtape_mutex);
};

void lck_mtx_init_ext(lck_mtx_t* lck, struct _lck_mtx_ext_* lck_ext, lck_grp_t* grp, lck_attr_t* attr) {
	lck_mtx_init(lck, grp, attr);
};

lck_mtx_t* lck_mtx_alloc_init(lck_grp_t* grp, lck_attr_t* attr) {
	lck_mtx_t* lck = kalloc(sizeof(lck_mtx_t));
	if (!lck) {
		return NULL;
	}
	lck_mtx_init(lck, grp, attr);
	return lck;
}

void lck_mtx_free(lck_mtx_t* lck, lck_grp_t* grp) {
	lck_mtx_destroy(lck, grp);
	kfree(lck, sizeof(lck_mtx_t));
};

//
// spin lock
//
// because duct-taped code runs in actual Linux threads and
// we can't disable preemption for real (not that we would want to),
// spin locks are just mutexes.
//

void lck_spin_init(lck_spin_t* lock, lck_grp_t* grp, lck_attr_t* attr) {
	lck_mtx_init(&lock->dtape_interlock, grp, attr);
};

void lck_spin_assert(lck_spin_t* lock, unsigned int type) {
	lck_mtx_assert(&lock->dtape_interlock, type);
};

void lck_spin_destroy(lck_spin_t* lock, lck_grp_t* grp) {
	lck_mtx_destroy(&lock->dtape_interlock, grp);
};

void lck_spin_lock(lck_spin_t* lock) {
	lck_mtx_lock(&lock->dtape_interlock);
};

boolean_t lck_spin_try_lock(lck_spin_t* lock) {
	return lck_mtx_try_lock(&lock->dtape_interlock);
};

void lck_spin_unlock(lck_spin_t* lock) {
	lck_mtx_unlock(&lock->dtape_interlock);
};

void lck_spin_lock_grp(lck_spin_t* lock, lck_grp_t* grp) {
	lck_spin_lock(lock);
};

boolean_t lck_spin_try_lock_grp(lck_spin_t* lock, lck_grp_t* grp) {
	return lck_spin_try_lock(lock);
};

//
// waitq lock
//

void waitq_lock_init(struct waitq* wq) {
	usimple_lock_init(&wq->dtape_waitq_interlock, 0);
};

void waitq_lock(struct waitq *wq) {
	usimple_lock(&wq->dtape_waitq_interlock, LCK_GRP_NULL);
};

void waitq_unlock(struct waitq *wq) {
	usimple_unlock(&wq->dtape_waitq_interlock);
};

unsigned int waitq_lock_try(struct waitq* wq) {
	return usimple_lock_try(&wq->dtape_waitq_interlock, LCK_GRP_NULL);
};

//
// usimple lock

void (usimple_lock)(usimple_lock_t lock) {
	lck_spin_lock(&lock->dtape_interlock);
};

void usimple_lock_init(usimple_lock_t lock, unsigned short tag) {
	lck_spin_init(&lock->dtape_interlock, LCK_GRP_NULL, LCK_ATTR_NULL);
};

void usimple_unlock(usimple_lock_t lock) {
	lck_spin_unlock(&lock->dtape_interlock);
};

unsigned int usimple_lock_try(usimple_lock_t lock, lck_grp_t* grp) {
	return lck_spin_try_lock(&lock->dtape_interlock);
};

//
// ticket lock
//

void lck_ticket_init(lck_ticket_t* tlock, lck_grp_t* grp) {
	lck_spin_init(&tlock->dtape_lock, LCK_GRP_NULL, LCK_ATTR_NULL);
};

void (lck_ticket_lock)(lck_ticket_t* tlock) {
	lck_spin_lock(&tlock->dtape_lock);
};

void lck_ticket_unlock(lck_ticket_t* tlock) {
	lck_spin_unlock(&tlock->dtape_lock);
};

void lck_ticket_assert_owned(lck_ticket_t* tlock) {
	lck_spin_assert(&tlock->dtape_lock, LCK_ASSERT_OWNED);
};

//
// read-write lock
//

lck_rw_type_t lck_rw_done(lck_rw_t* lock) {
	dtape_stub_unsafe();
};

void lck_rw_lock_exclusive(lck_rw_t* lock) {
	dtape_stub_unsafe();
};

void lck_rw_clear_promotion(thread_t thread, uintptr_t trace_obj) {
	dtape_stub_safe();
};

uintptr_t unslide_for_kdebug(void* object) {
	dtape_stub_safe();
	return 0;
};

#define LOCK_SNOOP_SPINS 100

// <copied from="xnu://7195.141.2/osfmk/kern/locks.c">

/*
 * Routine:	lck_spin_sleep
 */
wait_result_t
lck_spin_sleep_grp(
	lck_spin_t              *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	lck_grp_t               *grp)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x\n", lck_sleep_action);
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lock);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			lck_spin_lock_grp(lock, grp);
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_spin_unlock(lock);
	}

	return res;
}

/*
 * Routine:	lck_mtx_sleep
 */
wait_result_t
lck_mtx_sleep(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible)
{
	wait_result_t   res;
	thread_t                thread = current_thread();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x\n", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * We overload the RW lock promotion to give us a priority ceiling
		 * during the time that this thread is asleep, so that when it
		 * is re-awakened (and not yet contending on the mutex), it is
		 * runnable at a reasonably high priority.
		 */
		thread->rwlock_count++;
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else if ((lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS)) {
				lck_mtx_lock_spin_always(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */
			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
		}
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Routine:	lck_mtx_sleep_deadline
 */
wait_result_t
lck_mtx_sleep_deadline(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline)
{
	wait_result_t   res;
	thread_t                thread = current_thread();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_START,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0) {
		panic("Invalid lock sleep action %x\n", lck_sleep_action);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * See lck_mtx_sleep().
		 */
		thread->rwlock_count++;
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN)) {
				lck_mtx_lock_spin(lck);
			} else {
				lck_mtx_lock(lck);
			}
		}
	} else if (lck_sleep_action & LCK_SLEEP_UNLOCK) {
		lck_mtx_unlock(lck);
	}

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */
			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
		}
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Routine:     mutex_pause
 *
 * Called by former callers of simple_lock_pause().
 */
#define MAX_COLLISION_COUNTS    32
#define MAX_COLLISION   8

unsigned int max_collision_count[MAX_COLLISION_COUNTS];

uint32_t collision_backoffs[MAX_COLLISION] = {
	10, 50, 100, 200, 400, 600, 800, 1000
};


void
mutex_pause(uint32_t collisions)
{
	wait_result_t wait_result;
	uint32_t        back_off;

	if (collisions >= MAX_COLLISION_COUNTS) {
		collisions = MAX_COLLISION_COUNTS - 1;
	}
	max_collision_count[collisions]++;

	if (collisions >= MAX_COLLISION) {
		collisions = MAX_COLLISION - 1;
	}
	back_off = collision_backoffs[collisions];

	wait_result = assert_wait_timeout((event_t)mutex_pause, THREAD_UNINT, back_off, NSEC_PER_USEC);
	assert(wait_result == THREAD_WAITING);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
}

void *
hw_wait_while_equals(void **address, void *current)
{
	void *v;
	uint64_t end = 0;

	for (;;) {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
#ifdef __DARLING__
#if __x86_64__ || __i386__
			__builtin_ia32_pause();
#else
			#warning Missing CPU pause for this architecture
#endif
#else
			cpu_pause();
#endif
#if OS_ATOMIC_HAS_LLSC
			v = os_atomic_load_exclusive(address, relaxed);
			if (__probable(v != current)) {
				os_atomic_clear_exclusive();
				return v;
			}
			wait_for_event();
#else
			v = os_atomic_load(address, relaxed);
			if (__probable(v != current)) {
				return v;
			}
#endif // OS_ATOMIC_HAS_LLSC
		}
#ifndef __DARLING__
		if (end == 0) {
			end = ml_get_timebase() + LOCK_PANIC_TIMEOUT;
		} else if (ml_get_timebase() >= end) {
			panic("Wait while equals timeout @ *%p == %p", address, v);
		}
#endif // __DARLING__
	}
}

// </copied>
