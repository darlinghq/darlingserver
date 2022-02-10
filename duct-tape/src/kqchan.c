#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/kqchan.h>
#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/thread.h>

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

void dtape_kqchan_mach_port_fill(dtape_kqchan_mach_port_t* kqchan, dserver_kqchan_reply_mach_port_read_t* reply, uint64_t default_buffer, uint64_t default_buffer_size) {
	struct kevent_qos_s kev;
	bool maybe_used_default_buffer = false;
	thread_t xthread = current_thread();
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);

	thread->kevent_ctx.kec_data_out = thread->kevent_ctx.kec_data_avail = default_buffer;
	thread->kevent_ctx.kec_data_size = thread->kevent_ctx.kec_data_resid = default_buffer_size;
	thread->kevent_ctx.kec_process_flags = 0;

	filt_machportprocess(&kqchan->knote, (void*)&reply->kev);
};

bool dtape_kqchan_mach_port_has_events(dtape_kqchan_mach_port_t* kqchan) {
	return filt_machportpeek(&kqchan->knote) & FILTER_ACTIVE;
};

kevent_ctx_t kevent_get_context(thread_t xthread) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(xthread);
	return &thread->kevent_ctx;
};

void knote(struct klist* list, long hint) {
	struct knote *kn;

	SLIST_FOREACH(kn, list, kn_selnext) {
		dtape_kqchan_mach_port_t* kqchan = __container_of(kn, dtape_kqchan_mach_port_t, knote);

		if (!kqchan->callback) {
			continue;
		}

		imq_lock(kqchan->knote.kn_mqueue);

		if ((filt_machportevent(&kqchan->knote, hint) & FILTER_ACTIVE) == 0) {
			continue;
		}

		imq_unlock(kqchan->knote.kn_mqueue);

		kqchan->callback(kqchan->context);
	}
};

void knote_vanish(struct klist* list, bool make_active) {
	dtape_stub();
};

int knote_link_waitq(struct knote *kn, struct waitq *wq, uint64_t *reserved_link) {
	dtape_stub();
	return 0;
};

int knote_unlink_waitq(struct knote *kn, struct waitq *wq) {
	dtape_stub();
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
