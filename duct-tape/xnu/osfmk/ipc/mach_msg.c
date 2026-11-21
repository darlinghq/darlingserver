/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */
/*
 */
/*
 *	File:	ipc/mach_msg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Exported message traps.  See mach/message.h.
 */

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/mach_traps.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/exception.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/syscall_subr.h>
#include <kern/policy_internal.h>
#include <kern/mach_filter.h>

#include <vm/vm_map.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_voucher.h>

#include <machine/machine_routines.h>
#include <security/mac_mach_internal.h>

#include <sys/kdebug.h>

#ifdef __DARLING__
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/rpc-supplement.h>
#include <libsimple/lock.h>
#include <stdlib.h>

/*
 * Messages held for a restarted receive (see mach_msg_receive_results()) by threads that went away
 * before receiving them. A thread is destroyed where messages can't be destroyed (that may send
 * notifications), so they are destroyed by the next thread that enters mach_msg_overwrite_trap().
 * This is what happens on macOS to a message received by a thread that never returns from the
 * signal handler that interrupted it: nobody else gets it.
 */
struct dtape_abandoned_receive {
	struct dtape_abandoned_receive *next;
	ipc_kmsg_t kmsg;
	ipc_object_t object;
};

static libsimple_lock_t dtape_abandoned_receives_lock = LIBSIMPLE_LOCK_INITIALIZER;
static struct dtape_abandoned_receive *dtape_abandoned_receives;

void
dtape_thread_abandon_pending_receive(dtape_thread_t *thread)
{
	struct dtape_abandoned_receive *entry;

	dtape_thread_release_reserved_regions(thread, VM_MAP_NULL);

	if (thread->pending_receive_kmsg == IKM_NULL) {
		return;
	}

	entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		/* leak it rather than destroy it here */
		return;
	}
	entry->kmsg = thread->pending_receive_kmsg;
	entry->object = thread->pending_receive_object;
	thread->pending_receive_kmsg = IKM_NULL;
	thread->pending_receive_object = IO_NULL;

	libsimple_lock_lock(&dtape_abandoned_receives_lock);
	entry->next = dtape_abandoned_receives;
	dtape_abandoned_receives = entry;
	libsimple_lock_unlock(&dtape_abandoned_receives_lock);
}

static void
dtape_destroy_abandoned_receives(void)
{
	struct dtape_abandoned_receive *entry;

	if (__atomic_load_n(&dtape_abandoned_receives, __ATOMIC_RELAXED) == NULL) {
		return;
	}

	libsimple_lock_lock(&dtape_abandoned_receives_lock);
	entry = dtape_abandoned_receives;
	dtape_abandoned_receives = NULL;
	libsimple_lock_unlock(&dtape_abandoned_receives_lock);

	while (entry != NULL) {
		struct dtape_abandoned_receive *next = entry->next;
		ipc_kmsg_destroy(entry->kmsg);
		io_release(entry->object);
		free(entry);
		entry = next;
	}
}
#endif /* __DARLING__ */

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif /* offsetof */

/*
 * Forward declarations - kernel internal routines
 */

mach_msg_return_t mach_msg_send(
	mach_msg_header_t       *msg,
	mach_msg_option_t       option,
	mach_msg_size_t         send_size,
	mach_msg_timeout_t      send_timeout,
	mach_port_name_t        notify);

mach_msg_return_t mach_msg_receive(
	mach_msg_header_t       *msg,
	mach_msg_option_t       option,
	mach_msg_size_t         rcv_size,
	mach_port_name_t        rcv_name,
	mach_msg_timeout_t      rcv_timeout,
	void                    (*continuation)(mach_msg_return_t),
	mach_msg_size_t         slist_size);


mach_msg_return_t msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *out_size);

static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port);

void
mach_msg_receive_results_complete(ipc_object_t object);

const security_token_t KERNEL_SECURITY_TOKEN = KERNEL_SECURITY_TOKEN_VALUE;
const audit_token_t KERNEL_AUDIT_TOKEN = KERNEL_AUDIT_TOKEN_VALUE;

const mach_msg_max_trailer_t trailer_template = {
	.msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0,
	.msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE,
	.msgh_sender = KERNEL_SECURITY_TOKEN_VALUE,
	.msgh_audit = KERNEL_AUDIT_TOKEN_VALUE
};

/*
 *	Routine:	mach_msg_send [Kernel Internal]
 *	Purpose:
 *		Routine for kernel-task threads to send a message.
 *
 *		Unlike mach_msg_send_from_kernel(), this routine
 *		looks port names up in the kernel's port namespace
 *		and copies in the kernel virtual memory (instead
 *		of taking a vm_map_copy_t pointer for OOL descriptors).
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Sent the message.
 *		MACH_SEND_MSG_TOO_SMALL	Message smaller than a header.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate buffer.
 *		MACH_SEND_INVALID_DATA	Couldn't copy message data.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_NOTIFY	Bad notify port.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *		MACH_SEND_TIMED_OUT	Timeout expired without delivery.
 *		MACH_SEND_INTERRUPTED	Delivery interrupted.
 */

mach_msg_return_t
mach_msg_send(
	mach_msg_header_t       *msg,
	mach_msg_option_t       option,
	mach_msg_size_t         send_size,
	mach_msg_timeout_t      send_timeout,
	mach_msg_priority_t     priority)
{
	ipc_space_t space = current_space();
	vm_map_t map = current_map();
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr;
	mach_msg_size_t msg_and_trailer_size;
	mach_msg_max_trailer_t  *trailer;

	option |= MACH_SEND_KERNEL;

	if ((send_size & 3) ||
	    send_size < sizeof(mach_msg_header_t) ||
	    (send_size < sizeof(mach_msg_base_t) && (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX))) {
		return MACH_SEND_MSG_TOO_SMALL;
	}

	if (send_size > MACH_MSG_SIZE_MAX - MAX_TRAILER_SIZE) {
		return MACH_SEND_TOO_LARGE;
	}

	KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

	msg_and_trailer_size = send_size + MAX_TRAILER_SIZE;

	kmsg = ipc_kmsg_alloc(msg_and_trailer_size);

	if (kmsg == IKM_NULL) {
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, MACH_SEND_NO_BUFFER);
		return MACH_SEND_NO_BUFFER;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
	    (uintptr_t)0,                   /* this should only be called from the kernel! */
	    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
	    0, 0,
	    0);
	(void) memcpy((void *) kmsg->ikm_header, (const void *) msg, send_size);

	kmsg->ikm_header->msgh_size = send_size;

	/*
	 * reserve for the trailer the largest space (MAX_TRAILER_SIZE)
	 * However, the internal size field of the trailer (msgh_trailer_size)
	 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
	 * the cases where no implicit data is requested.
	 */
	trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + send_size);
	bzero(trailer, sizeof(*trailer));
	trailer->msgh_sender = current_thread()->task->sec_token;
	trailer->msgh_audit = current_thread()->task->audit_token;
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;

	mr = ipc_kmsg_copyin(kmsg, space, map, priority, &option);

	if (mr != MACH_MSG_SUCCESS) {
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
		return mr;
	}

	mr = ipc_kmsg_send(kmsg, option, send_timeout);

	if (mr != MACH_MSG_SUCCESS) {
		mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
		(void) memcpy((void *) msg, (const void *) kmsg->ikm_header,
		    kmsg->ikm_header->msgh_size);
		ipc_kmsg_free(kmsg);
		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
	}

	return mr;
}

/*
 * message header as seen at user-space
 * (for MACH_RCV_LARGE/IDENTITY updating)
 */
typedef struct{
	mach_msg_bits_t       msgh_bits;
	mach_msg_size_t       msgh_size;
	mach_port_name_t      msgh_remote_port;
	mach_port_name_t      msgh_local_port;
	mach_msg_size_t       msgh_reserved;
	mach_msg_id_t         msgh_id;
} mach_msg_user_header_t;

/*
 *	Routine:	mach_msg_receive_results
 *	Purpose:
 *		Receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Received a message.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right,
 *			or the denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 *		MACH_RCV_TOO_LARGE	Message wouldn't fit into buffer.
 *		MACH_RCV_TIMED_OUT	Timeout expired without a message.
 *		MACH_RCV_INTERRUPTED	Reception interrupted.
 *		MACH_RCV_PORT_DIED	Port/set died while receiving.
 *		MACH_RCV_PORT_CHANGED	Port moved into set while receiving.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user buffer.
 *		MACH_RCV_INVALID_NOTIFY	Bad notify port.
 *		MACH_RCV_HEADER_ERROR
 */

mach_msg_return_t
mach_msg_receive_results(
	mach_msg_size_t *sizep)
{
	thread_t          self = current_thread();
	ipc_space_t       space = current_space();
	vm_map_t          map = current_map();

	ipc_object_t      object = self->ith_object;
	mach_msg_return_t mr = self->ith_state;
	mach_vm_address_t rcv_addr = self->ith_msg_addr;
	mach_msg_size_t   rcv_size = self->ith_rsize;
	mach_msg_option_t option = self->ith_option;
	ipc_kmsg_t        kmsg = self->ith_kmsg;
	mach_port_seqno_t seqno = self->ith_seqno;

	mach_msg_trailer_size_t trailer_size;
	mach_vm_address_t context;
	mach_msg_size_t   size = 0;

#ifdef __DARLING__
	dtape_thread_t *dthread = dtape_thread_for_xnu_thread(self);
	boolean_t restart_allowed = dthread != NULL && dthread->receive_restart_allowed && IO_VALID(object);
	if (dthread != NULL) {
		dthread->receive_restart_allowed = FALSE;
	}
	if (restart_allowed) {
		/* kept with the message if it has to be held for a restarted receive */
		io_reference(object);
	}
#endif /* __DARLING__ */

	/*
	 * unlink the special_reply_port before releasing reference to object.
	 * get the thread's turnstile, if the thread donated it's turnstile to the port
	 */
	mach_msg_receive_results_complete(object);
	io_release(object);

	if (mr != MACH_MSG_SUCCESS) {
#ifdef __DARLING__
		if (restart_allowed) {
			io_release(object);
		}
#endif /* __DARLING__ */
		if (mr == MACH_RCV_TOO_LARGE) {
			/*
			 * If the receive operation occurs with MACH_RCV_LARGE set
			 * then no message was extracted from the queue, and the size
			 * and (optionally) receiver names were the only thing captured.
			 * Just copyout the size (and optional port name) in a fake
			 * header.
			 */
			if (option & MACH_RCV_LARGE) {
				if ((option & MACH_RCV_STACK) == 0 &&
				    rcv_size >= offsetof(mach_msg_user_header_t, msgh_reserved)) {
					/*
					 * We need to inform the user-level code that it needs more
					 * space.  The value for how much space was returned in the
					 * msize save area instead of the message (which was left on
					 * the queue).
					 */
					if (option & MACH_RCV_LARGE_IDENTITY) {
						if (copyout((char *) &self->ith_receiver_name,
						    rcv_addr + offsetof(mach_msg_user_header_t, msgh_local_port),
						    sizeof(mach_port_name_t))) {
							mr = MACH_RCV_INVALID_DATA;
						}
					}
					if (copyout((char *) &self->ith_msize,
					    rcv_addr + offsetof(mach_msg_user_header_t, msgh_size),
					    sizeof(mach_msg_size_t))) {
						mr = MACH_RCV_INVALID_DATA;
					}
				}
			} else {
				/* discard importance in message */
				ipc_importance_clean(kmsg);

				if (msg_receive_error(kmsg, option, rcv_addr, rcv_size, seqno, space, &size)
				    == MACH_RCV_INVALID_DATA) {
					mr = MACH_RCV_INVALID_DATA;
				}
			}
		}

		if (sizep) {
			*sizep = size;
		}
		return mr;
	}

	/* MACH_MSG_SUCCESS */

#ifdef __DARLING__
	if (restart_allowed) {
		if (dtape_kmsg_reserve_out_of_line(kmsg, map) != KERN_SUCCESS &&
		    dtape_hooks->current_thread_take_s2c_interrupted() &&
		    dthread->pending_receive_kmsg == IKM_NULL) {
			/*
			 * Mapping the message's out-of-line memory in this task was interrupted: a signal is being
			 * delivered to this thread. XNU never fails a receive (or loses its message) because of that,
			 * so hold the message, which is still intact, and have libsystem_kernel make the same call
			 * again once the signal has been handled; that call gets this message (see
			 * mach_msg_overwrite_trap()). The regions mapped so far are kept for it.
			 */
			dthread->pending_receive_kmsg = kmsg;
			dthread->pending_receive_object = object;
			dthread->pending_receive_seqno = seqno;
			if (sizep) {
				*sizep = 0;
			}
			return -DSERVER_RPC_RESTART;
		}
		/* any other failure is reported by the copyout, as without the reservation */
		io_release(object);
	}
#endif /* __DARLING__ */

#if IMPORTANCE_INHERITANCE

	/* adopt/transform any importance attributes carried in the message */
	ipc_importance_receive(kmsg, option);

#endif  /* IMPORTANCE_INHERITANCE */

	/* auto redeem the voucher in the message */
	ipc_voucher_receive_postprocessing(kmsg, option);

	/* Save destination port context for the trailer before copyout */
	context = kmsg->ikm_header->msgh_remote_port->ip_context;

	mr = ipc_kmsg_copyout(kmsg, space, map, MACH_MSG_BODY_NULL, option);

#ifdef __DARLING__
	if (dthread != NULL && dthread->reserved_region_count != 0) {
		/* regions the copyout didn't take (e.g. after a header error) */
		dtape_thread_release_reserved_regions(dthread, map);
	}
#endif /* __DARLING__ */

	trailer_size = ipc_kmsg_trailer_size(option, self);

	if (mr != MACH_MSG_SUCCESS) {
		/* already received importance, so have to undo that here */
		ipc_importance_unreceive(kmsg, option);

		/* if we had a body error copyout what we have, otherwise a simple header/trailer */
		if ((mr & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
			ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, FALSE, context);
			if (ipc_kmsg_put(kmsg, option, rcv_addr, rcv_size, trailer_size, &size) == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		} else {
			if (msg_receive_error(kmsg, option, rcv_addr, rcv_size, seqno, space, &size)
			    == MACH_RCV_INVALID_DATA) {
				mr = MACH_RCV_INVALID_DATA;
			}
		}
	} else {
		/* capture ksmg QoS values to the thread continuation state */
		self->ith_ppriority = kmsg->ikm_ppriority;
		self->ith_qos_override = kmsg->ikm_qos_override;
		ipc_kmsg_add_trailer(kmsg, space, option, self, seqno, FALSE, context);
		mr = ipc_kmsg_put(kmsg, option, rcv_addr, rcv_size, trailer_size, &size);
	}

	if (sizep) {
		*sizep = size;
	}
	return mr;
}

/*
 *	Routine:	mach_msg_receive [Kernel Internal]
 *	Purpose:
 *		Routine for kernel-task threads to actively receive a message.
 *
 *		Unlike being dispatched to by ipc_kobject_server() or the
 *		reply part of mach_msg_rpc_from_kernel(), this routine
 *		looks up the receive port name in the kernel's port
 *		namespace and copies out received port rights to that namespace
 *		as well.  Out-of-line memory is copied out the kernel's
 *		address space (rather than just providing the vm_map_copy_t).
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Received a message.
 *		See <mach/message.h> for list of MACH_RCV_XXX errors.
 */
mach_msg_return_t
mach_msg_receive(
	mach_msg_header_t       *msg,
	mach_msg_option_t       option,
	mach_msg_size_t         rcv_size,
	mach_port_name_t        rcv_name,
	mach_msg_timeout_t      rcv_timeout,
	void                    (*continuation)(mach_msg_return_t),
	__unused mach_msg_size_t slist_size)
{
	thread_t self = current_thread();
	ipc_space_t space = current_space();
	ipc_object_t object;
	ipc_mqueue_t mqueue;
	mach_msg_return_t mr;

	mr = ipc_mqueue_copyin(space, rcv_name, &mqueue, &object);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}
	/* hold ref for object */

	self->ith_msg_addr = CAST_DOWN(mach_vm_address_t, msg);
	self->ith_object = object;
	self->ith_rsize = rcv_size;
	self->ith_msize = 0;
	self->ith_option = option;
	self->ith_continuation = continuation;
	self->ith_knote = ITH_KNOTE_NULL;

	ipc_mqueue_receive(mqueue, option, rcv_size, rcv_timeout, THREAD_ABORTSAFE);
	if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0) {
		thread_poll_yield(self);
	}
	return mach_msg_receive_results(NULL);
}

void
mach_msg_receive_continue(void)
{
	mach_msg_return_t mr;
	thread_t self = current_thread();

	ipc_port_thread_group_unblocked();
	if (self->ith_state == MACH_PEEK_READY) {
		mr = MACH_PEEK_READY;
	} else {
		mr = mach_msg_receive_results(NULL);
	}
	(*self->ith_continuation)(mr);
}


/*
 *	Routine:	mach_msg_overwrite_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	mach_vm_address_t       msg_addr = args->msg;
	mach_msg_option_t       option = args->option;
	mach_msg_size_t         send_size = args->send_size;
	mach_msg_size_t         rcv_size = args->rcv_size;
	mach_port_name_t        rcv_name = args->rcv_name;
	mach_msg_timeout_t      msg_timeout = args->timeout;
	mach_msg_priority_t     priority = args->priority;
	mach_vm_address_t       rcv_msg_addr = args->rcv_msg;
	__unused mach_port_seqno_t temp_seqno = 0;

	mach_msg_return_t  mr = MACH_MSG_SUCCESS;
	vm_map_t map = current_map();

	/* Only accept options allowed by the user */
	option &= MACH_MSG_OPTION_USER;

#ifdef __DARLING__
	dtape_destroy_abandoned_receives();
#endif /* __DARLING__ */

	if (option & MACH_SEND_MSG) {
		ipc_space_t space = current_space();
		ipc_kmsg_t kmsg;

		KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_START);

		mr = ipc_kmsg_get(msg_addr, send_size, &kmsg);

		if (mr != MACH_MSG_SUCCESS) {
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			return mr;
		}

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_LINK) | DBG_FUNC_NONE,
		    (uintptr_t)msg_addr,
		    VM_KERNEL_ADDRPERM((uintptr_t)kmsg),
		    0, 0,
		    0);

		mr = ipc_kmsg_copyin(kmsg, space, map, priority, &option);

		if (mr != MACH_MSG_SUCCESS) {
			ipc_kmsg_free(kmsg);
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			goto end;
		}

#ifdef __DARLING__
		dtape_thread_t *dthread = dtape_thread_for_xnu_thread(current_thread());
		dthread->kobject_restart_allowed = true;
		dthread->kobject_restart_requested = false;
#endif /* __DARLING__ */

		mr = ipc_kmsg_send(kmsg, option, msg_timeout);

#ifdef __DARLING__
		boolean_t restart = dthread->kobject_restart_requested;
		dthread->kobject_restart_allowed = false;
		dthread->kobject_restart_requested = false;
		if (!restart) {
			/* a request that was handed back has now been sent again (or the sender went on without it) */
			dtape_thread_release_kept_descriptor(dthread);
		}
#endif /* __DARLING__ */

		if (mr != MACH_MSG_SUCCESS) {
			mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
#ifdef __DARLING__
			mach_msg_return_t put_mr = ipc_kmsg_put(kmsg, option, msg_addr, send_size, 0, NULL);
			if (restart && mr == MACH_SEND_INTERRUPTED && put_mr == MACH_MSG_SUCCESS) {
				/*
				 * A kernel object could not perform the request because of a signal (see ipc_kobject_server()).
				 * The message is back in the sender's buffer, as for an interrupted send; have libsystem_kernel
				 * send it again, whatever the options, once the signal has been handled.
				 */
				mr = -DSERVER_RPC_RESTART;
			}
#else
			(void) ipc_kmsg_put(kmsg, option, msg_addr, send_size, 0, NULL);
#endif /* __DARLING__ */
			KDBG(MACHDBG_CODE(DBG_MACH_IPC, MACH_IPC_KMSG_INFO) | DBG_FUNC_END, mr);
			goto end;
		}
	}

	if (option & MACH_RCV_MSG) {
		thread_t self = current_thread();
		ipc_space_t space = current_space();
		ipc_object_t object;
		ipc_mqueue_t mqueue;

		mr = ipc_mqueue_copyin(space, rcv_name, &mqueue, &object);
		if (mr != MACH_MSG_SUCCESS) {
			goto end;
		}
		/* hold ref for object */

		if ((option & MACH_RCV_SYNC_WAIT) && !(option & MACH_SEND_SYNC_OVERRIDE)) {
			ipc_port_t special_reply_port;
			special_reply_port = ip_object_to_port(object);
			/* link the special reply port to the destination */
			mr = mach_msg_rcv_link_special_reply_port(special_reply_port,
			    (mach_port_name_t)priority);
			if (mr != MACH_MSG_SUCCESS) {
				io_release(object);
				goto end;
			}
		}

		if (rcv_msg_addr != (mach_vm_address_t)0) {
			self->ith_msg_addr = rcv_msg_addr;
		} else {
			self->ith_msg_addr = msg_addr;
		}
		self->ith_object = object;
		self->ith_rsize = rcv_size;
		self->ith_msize = 0;
		self->ith_option = option;
		self->ith_receiver_name = MACH_PORT_NULL;
		self->ith_continuation = thread_syscall_return;
		self->ith_knote = ITH_KNOTE_NULL;

#ifdef __DARLING__
		dtape_thread_t *rcv_dthread = dtape_thread_for_xnu_thread(self);
		/* only a receive-only call can be made again without repeating anything (see mach_msg_receive_results()) */
		rcv_dthread->receive_restart_allowed = !(option & MACH_SEND_MSG);
		if (rcv_dthread->pending_receive_kmsg != IKM_NULL && rcv_dthread->pending_receive_object == object) {
			/* the receive restarted after a signal: it gets the message it had already dequeued */
			self->ith_kmsg = rcv_dthread->pending_receive_kmsg;
			self->ith_seqno = rcv_dthread->pending_receive_seqno;
			self->ith_state = MACH_MSG_SUCCESS;
			rcv_dthread->pending_receive_kmsg = IKM_NULL;
			rcv_dthread->pending_receive_object = IO_NULL;
			/* the held reference; mach_msg_receive_results() releases the one taken by ipc_mqueue_copyin() */
			io_release(object);
			mr = mach_msg_receive_results(NULL);
			goto end;
		}
#endif /* __DARLING__ */

		ipc_mqueue_receive(mqueue, option, rcv_size, msg_timeout, THREAD_ABORTSAFE);
		if ((option & MACH_RCV_TIMEOUT) && msg_timeout == 0) {
			thread_poll_yield(self);
		}
		mr = mach_msg_receive_results(NULL);
		goto end;
	}

end:
	ipc_port_thread_group_unblocked();
	return mr;
}

/*
 *	Routine:	mach_msg_rcv_link_special_reply_port
 *	Purpose:
 *		Link the special reply port(rcv right) to the
 *		other end of the sync ipc channel.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
static mach_msg_return_t
mach_msg_rcv_link_special_reply_port(
	ipc_port_t special_reply_port,
	mach_port_name_t dest_name_port)
{
	ipc_port_t dest_port = IP_NULL;
	kern_return_t kr;

	if (current_thread()->ith_special_reply_port != special_reply_port) {
		return MACH_RCV_INVALID_NOTIFY;
	}

	/* Copyin the destination port */
	if (!MACH_PORT_VALID(dest_name_port)) {
		return MACH_RCV_INVALID_NOTIFY;
	}

	kr = ipc_port_translate_send(current_space(), dest_name_port, &dest_port);
	if (kr == KERN_SUCCESS) {
		ip_reference(dest_port);
		ip_unlock(dest_port);

		/*
		 * The receive right of dest port might have gone away,
		 * do not fail the receive in that case.
		 */
		ipc_port_link_special_reply_port(special_reply_port,
		    dest_port, FALSE);

		ip_release(dest_port);
	}
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	mach_msg_receive_results_complete
 *	Purpose:
 *		Get thread's turnstile back from the object and
 *              if object is a special reply port then reset its
 *		linkage.
 *	Condition:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
void
mach_msg_receive_results_complete(ipc_object_t object)
{
	thread_t self = current_thread();
	ipc_port_t port = IPC_PORT_NULL;
	boolean_t get_turnstile = (self->turnstile == TURNSTILE_NULL);

	if (io_otype(object) == IOT_PORT) {
		port = ip_object_to_port(object);
	} else {
		assert(self->turnstile != TURNSTILE_NULL);
		return;
	}

	uint8_t flags = IPC_PORT_ADJUST_SR_ALLOW_SYNC_LINKAGE;

	/*
	 * Don't clear the ip_srp_msg_sent bit if...
	 */
	if (!((self->ith_state == MACH_RCV_TOO_LARGE && self->ith_option & MACH_RCV_LARGE) || //msg was too large and the next receive will get it
	    self->ith_state == MACH_RCV_INTERRUPTED ||
	    self->ith_state == MACH_RCV_TIMED_OUT ||
	    self->ith_state == MACH_RCV_PORT_CHANGED ||
	    self->ith_state == MACH_PEEK_READY)) {
		flags |= IPC_PORT_ADJUST_SR_RECEIVED_MSG;
	}

	if (port->ip_specialreply || get_turnstile) {
		ip_lock(port);
		ipc_port_adjust_special_reply_port_locked(port, NULL,
		    flags, get_turnstile);
	}
	assert(self->turnstile != TURNSTILE_NULL);
	/* thread now has a turnstile */
}

/*
 *	Routine:	mach_msg_trap [mach trap]
 *	Purpose:
 *		Possibly send a message; possibly receive a message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		All of mach_msg_send and mach_msg_receive error codes.
 */

mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
	kern_return_t kr;
	args->rcv_msg = (mach_vm_address_t)0;

	kr = mach_msg_overwrite_trap(args);
	return kr;
}


/*
 *	Routine:	msg_receive_error	[internal]
 *	Purpose:
 *		Builds a minimal header/trailer and copies it to
 *		the user message buffer.  Invoked when in the case of a
 *		MACH_RCV_TOO_LARGE or MACH_RCV_BODY_ERROR error.
 *	Conditions:
 *		Nothing locked.
 *		size - maximum buffer size on input,
 *		       actual copied-out size on output
 *	Returns:
 *		MACH_MSG_SUCCESS	minimal header/trailer copied
 *		MACH_RCV_INVALID_DATA	copyout to user buffer failed
 */

mach_msg_return_t
msg_receive_error(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_vm_address_t       rcv_addr,
	mach_msg_size_t         rcv_size,
	mach_port_seqno_t       seqno,
	ipc_space_t             space,
	mach_msg_size_t         *sizep)
{
	mach_vm_address_t       context;
	mach_msg_trailer_size_t trailer_size;
	mach_msg_max_trailer_t  *trailer;
	thread_t                self = current_thread();

	context = kmsg->ikm_header->msgh_remote_port->ip_context;

	/*
	 * Copy out the destination port in the message.
	 * Destroy all other rights and memory in the message.
	 */
	ipc_kmsg_copyout_dest(kmsg, space);

	/*
	 * Build a minimal message with the requested trailer.
	 */
	trailer = (mach_msg_max_trailer_t *)
	    ((vm_offset_t)kmsg->ikm_header +
	    mach_round_msg(sizeof(mach_msg_header_t)));
	kmsg->ikm_header->msgh_size = sizeof(mach_msg_header_t);
	bcopy((const char *)&trailer_template,
	    (char *)trailer,
	    sizeof(trailer_template));

	trailer_size = ipc_kmsg_trailer_size(option, self);
	ipc_kmsg_add_trailer(kmsg, space, option, self,
	    seqno, TRUE, context);

	/*
	 * Copy the message to user space and return the size
	 * (note that ipc_kmsg_put may also adjust the actual
	 * size copied out to user-space).
	 */
	if (ipc_kmsg_put(kmsg, option, rcv_addr, rcv_size, trailer_size, sizep) == MACH_RCV_INVALID_DATA) {
		return MACH_RCV_INVALID_DATA;
	} else {
		return MACH_MSG_SUCCESS;
	}
}

static SECURITY_READ_ONLY_LATE(mach_msg_fetch_filter_policy_cbfunc_t) mach_msg_fetch_filter_policy_callback = NULL;

kern_return_t
mach_msg_filter_register_callback(
	const struct mach_msg_filter_callbacks *callbacks)
{
	if (callbacks == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (callbacks->version >= MACH_MSG_FILTER_CALLBACKS_VERSION_0) {
		if (mach_msg_fetch_filter_policy_callback != NULL) {
			return KERN_FAILURE;
		}
		mach_msg_fetch_filter_policy_callback = callbacks->fetch_filter_policy;
	}

	return KERN_SUCCESS;
}

/* This function should only be called if the task and port allow message filtering */
boolean_t
mach_msg_fetch_filter_policy(
	void *port_label,
	mach_msg_id_t msgh_id,
	mach_msg_filter_id *fid)
{
	boolean_t ret = TRUE;

	if (mach_msg_fetch_filter_policy_callback == NULL) {
		*fid = MACH_MSG_FILTER_POLICY_ALLOW;
		return true;
	}
	ret = mach_msg_fetch_filter_policy_callback(current_task(), port_label, msgh_id, fid);

	return ret;
}
