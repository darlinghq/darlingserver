#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/hooks.h>

#include <sys/proc.h>
#include <sys/pthread_shims.h>

lck_grp_attr_t* pthread_lck_grp_attr = LCK_GRP_ATTR_NULL;
lck_grp_t* pthread_lck_grp = LCK_GRP_NULL;
lck_attr_t* pthread_lck_attr = LCK_ATTR_NULL;

uint32_t pthread_debug_tracing = 1;

extern int _psynch_cvbroad(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex, uint64_t mugen, uint64_t tid, uint32_t* retval);
extern int _psynch_cvclrprepost(proc_t p, user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags, int* retval);
extern int _psynch_cvsignal(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int threadport, user_addr_t mutex, uint64_t mugen, uint64_t tid, uint32_t flags, uint32_t* retval);
extern int _psynch_cvwait(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex, uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec, uint32_t* retval);
extern int _psynch_mutexdrop(proc_t p, user_addr_t mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags, uint32_t* retval);
extern int _psynch_mutexwait(proc_t p, user_addr_t mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags, uint32_t* retval);
extern int _psynch_rw_rdlock(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t* retval);
extern int _psynch_rw_unlock(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t* retval);
extern int _psynch_rw_wrlock(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t* retval);

extern void psynch_zoneinit(void);

extern void _pth_proc_hashinit(proc_t p);
extern void _pth_proc_hashdelete(proc_t p);

int dtape_psynch_cvbroad(uint64_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, uint64_t mutex, uint64_t mugen, uint64_t tid, uint32_t* retval) {
	return _psynch_cvbroad(current_proc(), cv, cvlsgen, cvudgen, flags, mutex, mugen, tid, retval);
};

int dtape_psynch_cvclrprepost(uint64_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags, uint32_t* retval) {
	return _psynch_cvclrprepost(current_proc(), cv, cvgen, cvugen, cvsgen, prepocnt, preposeq, flags, (int*)retval);
};

int dtape_psynch_cvsignal(uint64_t cv, uint64_t cvlsgen, uint32_t cvugen, int32_t threadport, uint64_t mutex, uint64_t mugen, uint64_t tid, uint32_t flags, uint32_t* retval) {
	return _psynch_cvsignal(current_proc(), cv, cvlsgen, cvugen, threadport, mutex, mugen, tid, flags, retval);
};

int dtape_psynch_cvwait(uint64_t cv, uint64_t cvlsgen, uint32_t cvugen, uint64_t mutex, uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec, uint32_t* retval) {
	return _psynch_cvwait(current_proc(), cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec, retval);
};

int dtape_psynch_mutexdrop(uint64_t mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags, uint32_t* retval) {
	return _psynch_mutexdrop(current_proc(), mutex, mgen, ugen, tid, flags, retval);
};

int dtape_psynch_mutexwait(uint64_t mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags, uint32_t* retval) {
	return _psynch_mutexwait(current_proc(), mutex, mgen, ugen, tid, flags, retval);
};

int dtape_psynch_rw_rdlock(uint64_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int32_t flags, uint32_t* retval) {
	return _psynch_rw_rdlock(current_proc(), rwlock, lgenval, ugenval, rw_wc, flags, retval);
};

int dtape_psynch_rw_unlock(uint64_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int32_t flags, uint32_t* retval) {
	return _psynch_rw_unlock(current_proc(), rwlock, lgenval, ugenval, rw_wc, flags, retval);
};

int dtape_psynch_rw_wrlock(uint64_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int32_t flags, uint32_t* retval) {
	return _psynch_rw_wrlock(current_proc(), rwlock, lgenval, ugenval, rw_wc, flags, retval);
};

void dtape_psynch_init(void) {
	pthread_list_mlock = lck_mtx_alloc_init(pthread_lck_grp, pthread_lck_attr);

	pth_global_hashinit();
	psynch_thcall = thread_call_allocate(psynch_wq_cleanup, NULL);
	psynch_zoneinit();
};

// NOTE:
// the psynch code doesn't actually access `proc_t` or `uthread_t`; it invokes the callbacks we give it in order to do that stuff.
// therefore, we can actually give it any context we like for those pointers. we just use our duct-taped task and thread structures.

struct proc* current_proc(void) {
	return (void*)dtape_task_for_xnu_task(current_task());
};

struct uthread* current_uthread(void) {
	return (void*)dtape_thread_for_xnu_thread(current_thread());
};

int proc_pid(proc_t proc) {
	dtape_task_t* task = (void*)proc;
	return task->saved_pid;
};

__attribute__((noreturn))
static void unix_syscall_return(int retval) {
	thread_syscall_return(retval);
	__builtin_unreachable();
};

static void act_set_astbsd(thread_t thread) {
	dtape_stub();
};

void* get_bsdthread_info(thread_t th) {
	return (void*)dtape_thread_for_xnu_thread(th);
};

#undef SHOULDissignal

static bool SHOULDissignal(dtape_task_t* task, dtape_thread_t* thread) {
	dtape_stub();
	return false;
};

//
// <adapted from="xnu://7195.141.2/bsd/kern/kern_synch.c">
//

__attribute__((noreturn))
static void
_sleep_continue( __unused void *parameter, wait_result_t wresult)
{
	dtape_task_t* p = (void*)current_proc();
	thread_t self  = current_thread();
	dtape_thread_t* ut;
	int sig, catch;
	int error = 0;
	int dropmutex, spinmutex;

	ut = get_bsdthread_info(self);
	catch     = ut->uu_pri & PCATCH;
	dropmutex = ut->uu_pri & PDROP;
	spinmutex = ut->uu_pri & PSPIN;

	switch (wresult) {
	case THREAD_TIMED_OUT:
		error = EWOULDBLOCK;
		break;
	case THREAD_AWAKENED:
		/*
		 * Posix implies any signal should be delivered
		 * first, regardless of whether awakened due
		 * to receiving event.
		 */
		if (!catch) {
			break;
		}
		OS_FALLTHROUGH;
	case THREAD_INTERRUPTED:
		if (catch) {
			if (thread_should_abort(self)) {
				error = EINTR;
			} else if (SHOULDissignal(p, ut)) {
#if 0
				if ((sig = CURSIG(p)) != 0) {
					if (p->p_sigacts->ps_sigintr & sigmask(sig)) {
						error = EINTR;
					} else {
						error = ERESTART;
					}
				}
				if (thread_should_abort(self)) {
					error = EINTR;
				}
#else
				dtape_stub_unsafe("_sleep_continue SHOULDissignal");
#endif
#if 0
			} else if ((ut->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
				/* due to thread cancel */
				error = EINTR;
			}
#else
			} else {
				dtape_stub("THREAD_INTERRUPTED IN _sleep_continue");
				error = EINTR;
			}
#endif
		} else {
			error = EINTR;
		}
		break;
	}

	if (error == EINTR || error == ERESTART) {
		act_set_astbsd(self);
	}

	if (ut->uu_mtx && !dropmutex) {
		if (spinmutex) {
			lck_mtx_lock_spin(ut->uu_mtx);
		} else {
			lck_mtx_lock(ut->uu_mtx);
		}
	}
	ut->uu_wchan = NULL;
	ut->uu_wmesg = NULL;

	unix_syscall_return((*ut->uu_continuation)(error));
}

/*
 * Give up the processor till a wakeup occurs
 * on chan, at which time the process
 * enters the scheduling queue at priority pri.
 * The most important effect of pri is that when
 * pri<=PZERO a signal cannot disturb the sleep;
 * if pri>PZERO signals will be processed.
 * If pri&PCATCH is set, signals will cause sleep
 * to return 1, rather than longjmp.
 * Callers of this routine must be prepared for
 * premature return, and check that the reason for
 * sleeping has gone away.
 *
 * if msleep was the entry point, than we have a mutex to deal with
 *
 * The mutex is unlocked before the caller is blocked, and
 * relocked before msleep returns unless the priority includes the PDROP
 * flag... if PDROP is specified, _sleep returns with the mutex unlocked
 * regardless of whether it actually blocked or not.
 */

static int
_sleep(
	caddr_t         chan,
	int             pri,
	const char      *wmsg,
	u_int64_t       abstime,
	int             (*continuation)(int),
	lck_mtx_t       *mtx)
{
	dtape_task_t* p;
	thread_t self = current_thread();
	dtape_thread_t* ut;
	int sig, catch;
	int dropmutex  = pri & PDROP;
	int spinmutex  = pri & PSPIN;
	int wait_result;
	int error = 0;

	ut = get_bsdthread_info(self);

	p = (dtape_task_t*)current_proc();

	if (pri & PCATCH) {
		catch = THREAD_ABORTSAFE;
	} else {
		catch = THREAD_UNINT;
	}

	/* set wait message & channel */
	ut->uu_wchan = chan;
	ut->uu_wmesg = wmsg ? wmsg : "unknown";

	if (mtx != NULL && chan != NULL && (thread_continue_t)continuation == THREAD_CONTINUE_NULL) {
		int     flags;

		if (dropmutex) {
			flags = LCK_SLEEP_UNLOCK;
		} else {
			flags = LCK_SLEEP_DEFAULT;
		}

		if (spinmutex) {
			flags |= LCK_SLEEP_SPIN;
		}

		if (abstime) {
			wait_result = lck_mtx_sleep_deadline(mtx, flags, chan, catch, abstime);
		} else {
			wait_result = lck_mtx_sleep(mtx, flags, chan, catch);
		}
	} else {
		if (chan != NULL) {
			assert_wait_deadline(chan, catch, abstime);
		}
		if (mtx) {
			lck_mtx_unlock(mtx);
		}

		if (catch == THREAD_ABORTSAFE) {
			if (SHOULDissignal(p, ut)) {
#if 0
				if ((sig = CURSIG(p)) != 0) {
					if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE) {
						goto block;
					}
					if (p->p_sigacts->ps_sigintr & sigmask(sig)) {
						error = EINTR;
					} else {
						error = ERESTART;
					}
					if (mtx && !dropmutex) {
						if (spinmutex) {
							lck_mtx_lock_spin(mtx);
						} else {
							lck_mtx_lock(mtx);
						}
					}
					goto out;
				}
#else
				dtape_stub_unsafe("_sleep:SHOULDissignal");
#endif
			}
			if (thread_should_abort(self)) {
				if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE) {
					goto block;
				}
				error = EINTR;

				if (mtx && !dropmutex) {
					if (spinmutex) {
						lck_mtx_lock_spin(mtx);
					} else {
						lck_mtx_lock(mtx);
					}
				}
				goto out;
			}
		}


block:
		if ((thread_continue_t)continuation != THREAD_CONTINUE_NULL) {
			ut->uu_continuation = continuation;
			ut->uu_pri  = (uint16_t)pri;
			ut->uu_mtx  = mtx;
			(void) thread_block(_sleep_continue);
			/* NOTREACHED */
		}

		wait_result = thread_block(THREAD_CONTINUE_NULL);

		if (mtx && !dropmutex) {
			if (spinmutex) {
				lck_mtx_lock_spin(mtx);
			} else {
				lck_mtx_lock(mtx);
			}
		}
	}

	switch (wait_result) {
	case THREAD_TIMED_OUT:
		error = EWOULDBLOCK;
		break;
	case THREAD_AWAKENED:
	case THREAD_RESTART:
		/*
		 * Posix implies any signal should be delivered
		 * first, regardless of whether awakened due
		 * to receiving event.
		 */
		if (catch != THREAD_ABORTSAFE) {
			break;
		}
		OS_FALLTHROUGH;
	case THREAD_INTERRUPTED:
		if (catch == THREAD_ABORTSAFE) {
			if (thread_should_abort(self)) {
				error = EINTR;
			} else if (SHOULDissignal(p, ut)) {
#if 0
				if ((sig = CURSIG(p)) != 0) {
					if (p->p_sigacts->ps_sigintr & sigmask(sig)) {
						error = EINTR;
					} else {
						error = ERESTART;
					}
				}
				if (thread_should_abort(self)) {
					error = EINTR;
				}
#else
				dtape_stub_unsafe("THREAD_INTERRUPTED SHOULDissignal");
#endif
#if 0
			} else if ((ut->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
				/* due to thread cancel */
				error = EINTR;
			}
#else
			} else {
				dtape_stub("THREAD_INTERRUPTED in _sleep");
				error = EINTR;
			}
#endif
		} else {
			error = EINTR;
		}
		break;
	}
out:
	if (error == EINTR || error == ERESTART) {
		act_set_astbsd(self);
	}
	ut->uu_wchan = NULL;
	ut->uu_wmesg = NULL;

	return error;
}

//
// </adapted>
//

//
// <copied from="xnu://7195.141.2/bsd/kern/kern_synch.c">
//

int
msleep(
	void            *chan,
	lck_mtx_t       *mtx,
	int             pri,
	const char      *wmsg,
	struct timespec         *ts)
{
	u_int64_t       abstime = 0;

	if (ts && (ts->tv_sec || ts->tv_nsec)) {
		nanoseconds_to_absolutetime((uint64_t)ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec, &abstime );
		clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}

	return _sleep((caddr_t)chan, pri, wmsg, abstime, (int (*)(int))0, mtx);
}

/*
 * Wake up all processes sleeping on chan.
 */
void
wakeup(void *chan)
{
	thread_wakeup((caddr_t)chan);
}

//
// </copied>
//

//
// <copied from="xnu://7195.141.2/bsd/kern/kern_time.c">
//

void
microuptime(
	struct timeval  *tvp)
{
	clock_sec_t             tv_sec;
	clock_usec_t    tv_usec;

	clock_get_system_microtime(&tv_sec, &tv_usec);

	tvp->tv_sec = tv_sec;
	tvp->tv_usec = tv_usec;
}

uint64_t
tvtoabstime(
	struct timeval  *tvp)
{
	uint64_t        result, usresult;

	clock_interval_to_absolutetime_interval(
		(uint32_t)tvp->tv_sec, NSEC_PER_SEC, &result);
	clock_interval_to_absolutetime_interval(
		tvp->tv_usec, NSEC_PER_USEC, &usresult);

	return result + usresult;
}

//
// </copied>
//

//
// <copied from="xnu://7195.141.2/bsd/kern/kern_subr.c">
//

LIST_HEAD(generic_hash_head, generic);

/*
 * General routine to allocate a hash table.
 */
void *
hashinit(int elements, int type __unused, u_long *hashmask)
{
	struct generic_hash_head *hashtbl;
	vm_size_t hashsize;

	if (elements <= 0) {
		panic("hashinit: bad cnt");
	}

	hashsize = 1UL << (fls(elements) - 1);
	hashtbl = kheap_alloc(KHEAP_DEFAULT, hashsize * sizeof(*hashtbl),
	    Z_WAITOK | Z_ZERO);
	if (hashtbl != NULL) {
		*hashmask = hashsize - 1;
	}
	return hashtbl;
}

void
hashdestroy(void *hash, int type __unused, u_long hashmask)
{
	struct generic_hash_head *hashtbl = hash;
	assert(powerof2(hashmask + 1));
	kheap_free(KHEAP_DEFAULT, hashtbl, (hashmask + 1) * sizeof(*hashtbl));
}

//
// </copied>
//

static vm_map_t shim_current_map(void) {
	return dtape_thread_for_xnu_thread(current_thread())->xnu_thread.map;
};

static uint32_t shim_get_task_threadmax(void) {
	return CONFIG_THREAD_MAX;
};

static void* shim_proc_get_pthhash(struct proc* proc) {
	dtape_task_t* task = (void*)proc;
	return task->p_pthhash;
};

static void shim_proc_set_pthhash(struct proc* proc, void* ptr) {
	dtape_task_t* task = (void*)proc;
	task->p_pthhash = ptr;
};

//
// <copied from="xnu://7195.141.2/bsd/pthread/pthread_shims.c">
//

static void shim_psynch_wait_cleanup(void) {
	turnstile_cleanup();
};

static void shim_psynch_wait_complete(uintptr_t kwq, struct turnstile** tstore) {
	assert(tstore);
	turnstile_complete(kwq, tstore, NULL, TURNSTILE_PTHREAD_MUTEX);
};

static wait_result_t shim_psynch_wait_prepare(uintptr_t kwq, struct turnstile** tstore, thread_t owner, block_hint_t block_hint, uint64_t deadline) {
	struct turnstile *ts;
	wait_result_t wr;

	if (tstore) {
		ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL,
		    TURNSTILE_PTHREAD_MUTEX);

		turnstile_update_inheritor(ts, owner,
		    (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

		thread_set_pending_block_hint(current_thread(), block_hint);

		wr = waitq_assert_wait64_leeway(&ts->ts_waitq, (event64_t)kwq,
		    THREAD_ABORTSAFE, TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
	} else {
		thread_set_pending_block_hint(current_thread(), block_hint);

		wr = assert_wait_deadline_with_leeway((event_t)kwq, THREAD_ABORTSAFE,
		    TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
	}

	return wr;
};

static void shim_psynch_wait_update_complete(struct turnstile* ts) {
	assert(ts);
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);
};

static void shim_psynch_wait_update_owner(uintptr_t kwq, thread_t owner, struct turnstile** tstore) {
	struct turnstile *ts;

	ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL,
	    TURNSTILE_PTHREAD_MUTEX);

	turnstile_update_inheritor(ts, owner,
	    (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete(kwq, tstore, NULL, TURNSTILE_PTHREAD_MUTEX);
};

//
// </copied>
//

//
// <adapted from="xnu://7195.141.2/bsd/pthread/pthread_shims.c">
//

static kern_return_t shim_psynch_wait_wakeup(uintptr_t kwq, struct ksyn_waitq_element* kwe, struct turnstile** tstore) {
	dtape_thread_t* thread = __container_of((void*)kwe, dtape_thread_t, kwe);
	struct turnstile *ts;
	kern_return_t kr;

	if (tstore) {
		ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL, TURNSTILE_PTHREAD_MUTEX);
		turnstile_update_inheritor(ts, &thread->xnu_thread, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));

		kr = waitq_wakeup64_thread(&ts->ts_waitq, (event64_t)kwq, &thread->xnu_thread, THREAD_AWAKENED);

		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		turnstile_complete(kwq, tstore, NULL, TURNSTILE_PTHREAD_MUTEX);
	} else {
		kr = thread_wakeup_thread((event_t)kwq, &thread->xnu_thread);
	}

	return kr;
};

//
// </adapted>
//

static void shim___pthread_testcancel(int presyscall) {
	dtape_stub();
};

static void* shim_uthread_get_uukwe(struct uthread* uthread) {
	dtape_thread_t* thread = (void*)uthread;
	return &thread->kwe;
};

static int shim_uthread_is_cancelled(struct uthread* uthread) {
	dtape_stub();
	return 0;
};

void shim_uthread_set_returnval(struct uthread* uthread, int retval) {
	dtape_hooks->current_thread_set_bsd_retval(retval);
};

static const struct pthread_callbacks_s pthread_kern_real = {
	.current_map                 = shim_current_map,
	.get_bsdthread_info          = (void*)get_bsdthread_info,
	.get_task_threadmax          = shim_get_task_threadmax,
	.proc_get_pthhash            = shim_proc_get_pthhash,
	.proc_set_pthhash            = shim_proc_set_pthhash,
	.psynch_wait_cleanup         = shim_psynch_wait_cleanup,
	.psynch_wait_complete        = shim_psynch_wait_complete,
	.psynch_wait_prepare         = shim_psynch_wait_prepare,
	.psynch_wait_update_complete = shim_psynch_wait_update_complete,
	.psynch_wait_update_owner    = shim_psynch_wait_update_owner,
	.psynch_wait_wakeup          = shim_psynch_wait_wakeup,
	.__pthread_testcancel        = shim___pthread_testcancel,
	.task_findtid                = task_findtid,
	.thread_deallocate_safe      = thread_deallocate_safe,
	.unix_syscall_return         = unix_syscall_return,
	.uthread_get_uukwe           = shim_uthread_get_uukwe,
	.uthread_is_cancelled        = shim_uthread_is_cancelled,
	.uthread_set_returnval       = shim_uthread_set_returnval,
};

pthread_callbacks_t pthread_kern = &pthread_kern_real;

void dtape_psynch_task_init(dtape_task_t* task) {
	_pth_proc_hashinit((void*)task);
};

void dtape_psynch_task_destroy(dtape_task_t* task) {
	_pth_proc_hashdelete((void*)task);
};

void dtape_psynch_thread_init(dtape_thread_t* thread) {
	// nothing for now
};

void dtape_psynch_thread_destroy(dtape_thread_t* thread) {
	// nothing for now
};
