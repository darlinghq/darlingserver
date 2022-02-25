#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/kqchan.h>
#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/debug.h>
#include <stdlib.h>
#include <ipc/ipc_mqueue.h>
#include <kern/thread.h>

extern int filt_machportattach(struct knote *kn, struct kevent_qos_s *kev);
extern void filt_machportdetach(struct knote *kn);
extern int filt_machportevent(struct knote *kn, long hint);
extern int filt_machporttouch(struct knote *kn, struct kevent_qos_s *kev);
extern int filt_machportprocess(struct knote *kn, struct kevent_qos_s *kev);
extern int filt_machportpeek(struct knote *kn);

dtape_kqchan_mach_port_t* dtape_kqchan_mach_port_create(uint32_t port, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, dtape_kqchan_mach_port_notification_callback_f notification_callback, void* context) {
	dtape_kqchan_mach_port_t* kqchan = malloc(sizeof(dtape_kqchan_mach_port_t));
	if (!kqchan) {
		return NULL;
	}

	memset(kqchan, 0, sizeof(*kqchan));

	kqchan->callback = notification_callback;
	kqchan->context = context;

	os_ref_init(&kqchan->refcount, NULL);

	kqchan->knote.kn_id = port;
	kqchan->knote.kn_ext[0] = receive_buffer;
	kqchan->knote.kn_ext[1] = receive_buffer_size;
	kqchan->knote.kn_sfflags = saved_filter_flags;
	kqchan->knote.kn_filter = EVFILT_MACHPORT;

	// try to attach to the Mach port
	filt_machportattach(&kqchan->knote, NULL);

	if (kqchan->knote.kn_flags & EV_ERROR) {
		free(kqchan);
		return NULL;
	}

	return kqchan;
};

void dtape_kqchan_mach_port_destroy(dtape_kqchan_mach_port_t* kqchan) {
	if (os_ref_release(&kqchan->refcount) != 0) {
		panic("Duct-taped Mach port kqchan over-retained or still in-use at destruction");
	}

	filt_machportdetach(&kqchan->knote);

	free(kqchan);
};

void dtape_kqchan_mach_port_modify(dtape_kqchan_mach_port_t* kqchan, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags) {
	struct kevent_qos_s kev = {
		.fflags = saved_filter_flags,
		.ext = { receive_buffer, receive_buffer_size },
	};
	filt_machporttouch(&kqchan->knote, &kev);
};

void dtape_kqchan_mach_port_disable_notifications(dtape_kqchan_mach_port_t* kqchan) {
	kqchan->callback = NULL;
	kqchan->context = NULL;
};

bool dtape_kqchan_mach_port_fill(dtape_kqchan_mach_port_t* kqchan, dserver_kqchan_reply_mach_port_read_t* reply, uint64_t default_buffer, uint64_t default_buffer_size) {
	struct kevent_qos_s kev;
	bool maybe_used_default_buffer = false;
	thread_t xthread = current_thread();
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	thread->kevent_ctx.kec_data_out = thread->kevent_ctx.kec_data_avail = default_buffer;
	thread->kevent_ctx.kec_data_size = thread->kevent_ctx.kec_data_resid = default_buffer_size;
	thread->kevent_ctx.kec_process_flags = 0;

	bool result = (filt_machportprocess(&kqchan->knote, (void*)&reply->kev) & FILTER_ACTIVE) ? true : false;
	if (kqchan->waiter_read_semaphore) {
		dtape_semaphore_up(kqchan->waiter_read_semaphore);
	}
	return result;
};

bool dtape_kqchan_mach_port_has_events(dtape_kqchan_mach_port_t* kqchan) {
	if (imq_is_set(kqchan->knote.kn_mqueue)) {
		return ipc_mqueue_peek(kqchan->knote.kn_mqueue, NULL, NULL, NULL, NULL, NULL);
	} else {
		return ipc_mqueue_set_peek(kqchan->knote.kn_mqueue);
	}
};

kevent_ctx_t kevent_get_context(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	return &thread->kevent_ctx;
};

static void knote_post(struct knote* kn, long hint) {
	dtape_kqchan_mach_port_t* kqchan = __container_of(kn, dtape_kqchan_mach_port_t, knote);

	if (!kqchan->callback) {
		return;
	}

	if (dtape_kqchan_mach_port_has_events(kqchan)) {
		return;
	}

	kqchan->callback(kqchan->context);
};

void knote(struct klist* list, long hint) {
	struct knote *kn;

	SLIST_FOREACH(kn, list, kn_selnext) {
		knote_post(kn, hint);
	}
};

void knote_vanish(struct klist* list, bool make_active) {
	dtape_stub();
};

static void kqchan_waitq_waiter_entry(void* context, wait_result_t wait_result) {
	dtape_kqchan_mach_port_t* kqchan = context;
	struct waitq* wq = NULL;

	dtape_log_debug("kqchan waitq waiter thread entering");

	while ((wq = kqchan->waitq) != NULL) {
		if ((wait_result = waitq_assert_wait64(wq, IPC_MQUEUE_RECEIVE, THREAD_INTERRUPTIBLE, 0)) == THREAD_WAITING) {
			wait_result = thread_block(NULL);
		}

		dtape_log_debug("kqchan waitq waiter thread unblocked with wait result: %d", wait_result);

		if (wait_result == THREAD_INTERRUPTED) {
			// a wakeup with "THREAD_INTERRUPTED" indicates we should die
			break;
		} else {
			if (filt_machportpeek(&kqchan->knote) & FILTER_ACTIVE) {
				kqchan->callback(kqchan->context);
			}
			// wait until it's read
			if (!dtape_semaphore_down_simple(kqchan->waiter_read_semaphore)) {
				// we got interrupted
				break;
			}
		}
	}

	dtape_log_debug("kqchan waitq waiter thread exiting");

	// to prevent us from racing with the kqchan's death/deallocation, we have a death semaphore that the kqchan waits for before dying
	dtape_semaphore_up(kqchan->waiter_death_semaphore);

	thread_terminate_self();
	__builtin_unreachable();
};

int knote_link_waitq(struct knote *kn, struct waitq *wq, uint64_t *reserved_link) {
	dtape_kqchan_mach_port_t* kqchan = __container_of(kn, dtape_kqchan_mach_port_t, knote);

	if (kqchan->waitq) {
		dtape_log_warning("Attempt to link kqchan to %p while it was already linked to %p", wq, kqchan->waitq);
		return 1;
	}

	kqchan->waitq = wq;
	kqchan->waiter_death_semaphore = dtape_semaphore_create(dtape_task_for_xnu_task(kernel_task), 0);
	kqchan->waiter_read_semaphore = dtape_semaphore_create(dtape_task_for_xnu_task(kernel_task), 0);

	if (kernel_thread_start(kqchan_waitq_waiter_entry, kqchan, &kqchan->waiter_thread) != KERN_SUCCESS) {
		return 1;
	}

	return 0;
};

int knote_unlink_waitq(struct knote *kn, struct waitq *wq) {
	dtape_kqchan_mach_port_t* kqchan = __container_of(kn, dtape_kqchan_mach_port_t, knote);

	if (kqchan->waitq != wq) {
		panic("Attempt to unlink kqchan from %p while it was linked to %p", wq, kqchan->waitq);
	}

	// the kernel thread will see this and terminate if it's not currently blocked waiting
	kqchan->waitq = NULL;

	// if the kernel thread *is* currently blocked waiting, wake it up with THREAD_INTERRUPTED (it will know it needs to terminate)
	clear_wait(kqchan->waiter_thread, THREAD_INTERRUPTED);

	// now release our reference on the kernel thread
	thread_deallocate(kqchan->waiter_thread);
	kqchan->waiter_thread = NULL;

	// wait for the waiter thread to die
	dtape_semaphore_down_simple(kqchan->waiter_death_semaphore);

	// now destroy the waiter thread death semaphore
	dtape_semaphore_destroy(kqchan->waiter_death_semaphore);
	kqchan->waiter_death_semaphore = NULL;

	dtape_semaphore_destroy(kqchan->waiter_read_semaphore);
	kqchan->waiter_read_semaphore = NULL;

	return 0;
};

void knote_link_waitqset_lazy_alloc(struct knote *kn) {
	dtape_stub();
};

boolean_t knote_link_waitqset_should_lazy_alloc(struct knote *kn) {
	dtape_stub_safe();
	return FALSE;
};

struct turnstile* kqueue_alloc_turnstile(struct kqueue* kq) {
	dtape_stub();
	return NULL;
};

// <copied from="xnu://7195.141.2/bsd/kern/kern_event.c">

void
klist_init(struct klist *list)
{
	SLIST_INIT(list);
}

/*!
 * @function knote_fill_kevent_with_sdata
 *
 * @brief
 * Fills in a kevent from the current content of a knote.
 *
 * @discussion
 * This is meant to be called from filter's f_event hooks.
 * The kevent data is filled with kn->kn_sdata.
 *
 * kn->kn_fflags is cleared if kn->kn_flags has EV_CLEAR set.
 *
 * Using knote_fill_kevent is typically preferred.
 */
OS_ALWAYS_INLINE
void
knote_fill_kevent_with_sdata(struct knote *kn, struct kevent_qos_s *kev)
{
#define knote_assert_aliases(name1, offs1, name2) \
	static_assert(offsetof(struct kevent_qos_s, name1) + offs1 == \
	    offsetof(struct kevent_internal_s, name2), \
	        "kevent_qos_s::" #name1 " and kevent_internal_s::" #name2 "need to alias")
	/*
	 * All the code makes assumptions on these aliasing,
	 * so make sure we fail the build if we ever ever ever break them.
	 */
	knote_assert_aliases(ident, 0, kei_ident);
#ifdef __LITTLE_ENDIAN__
	knote_assert_aliases(filter, 0, kei_filter);  // non trivial overlap
	knote_assert_aliases(filter, 1, kei_filtid);  // non trivial overlap
#else
	knote_assert_aliases(filter, 0, kei_filtid);  // non trivial overlap
	knote_assert_aliases(filter, 1, kei_filter);  // non trivial overlap
#endif
	knote_assert_aliases(flags, 0, kei_flags);
	knote_assert_aliases(qos, 0, kei_qos);
	knote_assert_aliases(udata, 0, kei_udata);
	knote_assert_aliases(fflags, 0, kei_fflags);
	knote_assert_aliases(xflags, 0, kei_sfflags); // non trivial overlap
	knote_assert_aliases(data, 0, kei_sdata);     // non trivial overlap
	knote_assert_aliases(ext, 0, kei_ext);
#undef knote_assert_aliases

	/*
	 * Fix the differences between kevent_qos_s and kevent_internal_s:
	 * - xflags is where kn_sfflags lives, we need to zero it
	 * - fixup the high bits of `filter` where kn_filtid lives
	 */
	*kev = *(struct kevent_qos_s *)&kn->kn_kevent;
	kev->xflags = 0;
	kev->filter |= 0xff00;
	if (kn->kn_flags & EV_CLEAR) {
		kn->kn_fflags = 0;
	}
}

/*!
 * @function knote_fill_kevent
 *
 * @brief
 * Fills in a kevent from the current content of a knote.
 *
 * @discussion
 * This is meant to be called from filter's f_event hooks.
 * The kevent data is filled with the passed in data.
 *
 * kn->kn_fflags is cleared if kn->kn_flags has EV_CLEAR set.
 */
OS_ALWAYS_INLINE
void
knote_fill_kevent(struct knote *kn, struct kevent_qos_s *kev, int64_t data)
{
	knote_fill_kevent_with_sdata(kn, kev);
	kev->filter = kn->kn_filter;
	kev->data = data;
}

/*
 * attach a knote to the specified list.  Return true if this is the first entry.
 * The list is protected by whatever lock the object it is associated with uses.
 */
int
knote_attach(struct klist *list, struct knote *kn)
{
	int ret = SLIST_EMPTY(list);
	SLIST_INSERT_HEAD(list, kn, kn_selnext);
	return ret;
}

/*
 * detach a knote from the specified list.  Return true if that was the last entry.
 * The list is protected by whatever lock the object it is associated with uses.
 */
int
knote_detach(struct klist *list, struct knote *kn)
{
	SLIST_REMOVE(list, kn, knote, kn_selnext);
	return SLIST_EMPTY(list);
}

OS_ALWAYS_INLINE
void
knote_set_error(struct knote *kn, int error)
{
	kn->kn_flags |= EV_ERROR;
	kn->kn_sdata = error;
}

// </copied>
