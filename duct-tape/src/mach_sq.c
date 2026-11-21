/*
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Lubos Dolezel
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

// darlingserver's side of shared message queues (see darlingserver/mach-sq.h).
//
// The port, its rights and names stay in XNU's ipc code; only the queue of a port in shared-queue mode
// lives in the task's region. The server
//   - puts a new plain receive right of a task with a region in the mode (dtape_sq_port_created());
//   - delivers every message it sends to such a port as a token node, keeping the kmsg here
//     (dtape_sq_mqueue_send());
//   - receives from such a port by taking the head node, whatever its kind (dtape_sq_mqueue_receive());
//   - mirrors the state the task's own operations need: the rights of the receive right's name, the
//     context and qlimit of the port, the task's audit token history;
//   - takes the port out of the mode whenever anything else would need the queue (dtape_sq_port_leave()).
//     That is two fetch-or operations and a bounded walk: nothing here ever waits for the task.
//
// Locks: the port lock, then the mqueue lock, then the region lock (innermost; nothing is taken under it).
// Every change of a slot's queue words by the server is made with the mqueue lock held.

#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/mach_sq.h>
#include <darlingserver/mach-sq.h>

#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ipc_kobject.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <mach/mach_traps.h>

#include <stdlib.h>

// bounds of the server's loops over words the task can also change
#define SQ_ATTEMPTS 64

typedef struct dtape_sq_slot {
	struct dtape_sq_region* region;
	uint32_t index;
	uint32_t next_free;
	ipc_port_t port;            // NULL while the slot is free
	mach_port_name_t name;      // the receive right's name
	uint32_t rights;            // DSQ_RIGHT_* recorded in the name table
	uint32_t tokens_published;  // token ids: published in id order, and taken in that order too
	uint32_t tokens_taken;
	// closed, but its queue has not been moved to the port yet: whatever next has the port locked does that
	bool closing;
	struct ipc_kmsg_queue tokens;
} dtape_sq_slot_t;

typedef struct dtape_sq_history_entry {
	uint32_t gen;
	security_token_t sec_token;
	audit_token_t audit_token;
} dtape_sq_history_entry_t;

typedef struct dtape_sq_region {
	lck_spin_t lock;
	dsq_view_t view;
	bool poisoned;
	dtape_task_t* task;
	uint32_t free_slot;
	uint32_t snode_free_count;
	uint16_t snode_free[DSQ_SNODES];
	uint32_t gen;
	dtape_sq_history_entry_t history[DSQ_TOKEN_HISTORY];
	dtape_sq_slot_t slots[DSQ_SLOTS];
} dtape_sq_region_t;

static inline dtape_sq_slot_t* sq_port_slot(ipc_port_t port)
{
	return __atomic_load_n(&port->ip_sq, __ATOMIC_ACQUIRE);
}

// wakes the task's threads waiting on a queue word (the futex word is its low half)
static void sq_wake_count(dtape_sq_region_t* region, uint64_t* word, int count)
{
	dtape_hooks->sq_futex_wake((void*) word, count);
}

// all of them: after a close, every waiter has to look
static void sq_wake(dtape_sq_region_t* region, uint64_t* word)
{
	sq_wake_count(region, word, INT32_MAX);
}

static void sq_close_for_later(dtape_sq_slot_t* slot);

// region lock held
static void sq_poison(dtape_sq_region_t* region, const char* why)
{
	if (region->poisoned) {
		return;
	}
	region->poisoned = true;
	__atomic_or_fetch(&region->view.s->hdr.flags, DSQ_FLAG_POISONED, __ATOMIC_RELEASE);
	dtape_log_error("%d: shared message queues disabled for this task: %s", region->task->saved_pid, why);

	// every slot closes now; each port's queue moves to the port the next time the server has it locked
	for (uint32_t i = 0; i < DSQ_SLOTS; i++) {
		dtape_sq_slot_t* slot = &region->slots[i];
		if (slot->port != IP_NULL && !slot->closing) {
			sq_close_for_later(slot);
		}
	}
}

static void sq_record_tokens_locked(dtape_sq_region_t* region)
{
	task_t task = &region->task->xnu_task;
	dtape_sq_history_entry_t* e;

	region->gen = dsq_tokens_current(&region->view) + 1;
	e = &region->history[region->gen % DSQ_TOKEN_HISTORY];
	e->gen = region->gen;
	e->sec_token = task->sec_token;
	e->audit_token = task->audit_token;
	dsq_tokens_push(&region->view, (const uint32_t*) &task->sec_token, (const uint32_t*) &task->audit_token);
}

// the tokens of a message sent under generation `gen`; a generation that is no longer known (or that the
// task made up) gives the current tokens, so the task can't claim tokens it never had
static const dtape_sq_history_entry_t* sq_history(dtape_sq_region_t* region, uint32_t gen)
{
	const dtape_sq_history_entry_t* e = &region->history[gen % DSQ_TOKEN_HISTORY];
	if (e->gen != gen) {
		e = &region->history[region->gen % DSQ_TOKEN_HISTORY];
	}
	return e;
}

bool dtape_sq_attach(dtape_task_t* task, void* s_map, void* q_map)
{
	dtape_sq_region_t* region = malloc(sizeof(*region));
	if (!region) {
		return false;
	}
	memset(region, 0, sizeof(*region));

	lck_spin_init(&region->lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	region->view.s = s_map;
	region->view.q = q_map;
	region->task = task;

	for (uint32_t i = 0; i < DSQ_SLOTS; i++) {
		region->slots[i].region = region;
		region->slots[i].index = i;
		region->slots[i].next_free = (i + 1 < DSQ_SLOTS) ? i + 1 : UINT32_MAX;
		ipc_kmsg_queue_init(&region->slots[i].tokens);
	}
	region->free_slot = 0;
	for (uint32_t i = 0; i < DSQ_SNODES; i++) {
		region->snode_free[i] = (uint16_t) (DSQ_TNODES + DSQ_SNODES - 1 - i);
	}
	region->snode_free_count = DSQ_SNODES;

	dsq_region_init(&region->view);

	task_lock(&task->xnu_task);
	sq_record_tokens_locked(region);
	task_unlock(&task->xnu_task);

	dtape_sq_region_t* expected = NULL;
	if (!__atomic_compare_exchange_n(&task->sq_region, &expected, region, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		lck_spin_destroy(&region->lock, LCK_GRP_NULL);
		free(region);
		return false;
	}
	return true;
}

void dtape_sq_task_tokens_changed(dtape_task_t* task)
{
	dtape_sq_region_t* region = __atomic_load_n(&task->sq_region, __ATOMIC_ACQUIRE);
	if (!region) {
		return;
	}
	task_lock(&task->xnu_task);
	lck_spin_lock(&region->lock);
	sq_record_tokens_locked(region);
	lck_spin_unlock(&region->lock);
	task_unlock(&task->xnu_task);
}

void dtape_sq_task_destroy(dtape_task_t* task)
{
	dtape_sq_region_t* region = task->sq_region;
	if (!region) {
		return;
	}
	task->sq_region = NULL;

	// the space has been terminated, so every port has left the mode
	for (uint32_t i = 0; i < DSQ_SLOTS; i++) {
		if (region->slots[i].port != IP_NULL) {
			dtape_log_error("%d: a port is still in shared-queue mode after its space was terminated", task->saved_pid);
		}
	}

	dtape_hooks->sq_region_release(region->view.s, DSQ_S_SIZE, region->view.q, DSQ_Q_SIZE);
	lck_spin_destroy(&region->lock, LCK_GRP_NULL);
	free(region);
}

static bool sq_port_eligible(ipc_port_t port)
{
	return ip_active(port) &&
	       !ip_is_kobject(port) &&
	       !port->ip_specialreply &&
	       !port->ip_impdonation &&
	       !port->ip_tempowner &&
	       !IP_PREALLOC(port) &&
	       !ip_enforce_msg_filtering(port) &&
	       port->ip_in_pset == 0 &&
	       port->ip_sync_link_state == PORT_SYNC_LINK_ANY &&
	       SLIST_EMPTY(&port->ip_messages.imq_klist) &&
	       port->ip_nsrequest == IP_NULL &&
	       !port->ip_sprequests &&
	       port->ip_messages.imq_msgcount == 0 &&
	       ipc_kmsg_queue_empty(&port->ip_messages.imq_messages);
}

void dtape_sq_port_created(ipc_space_t space, mach_port_name_t name)
{
	task_t xtask = current_task();
	dtape_task_t* task;
	dtape_sq_region_t* region;
	ipc_entry_t entry;
	ipc_port_t port;

	if (!xtask || xtask->itk_space != space) {
		return;
	}
	task = dtape_task_for_xnu_task(xtask);
	region = __atomic_load_n(&task->sq_region, __ATOMIC_ACQUIRE);
	if (!region || region->poisoned) {
		return;
	}

	is_read_lock(space);
	if (!is_active(space)) {
		goto out_space;
	}
	entry = ipc_entry_lookup(space, name);
	if (entry == IE_NULL || (entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0) {
		goto out_space;
	}
	port = ip_object_to_port(entry->ie_object);

	ip_lock(port);
	if (!sq_port_eligible(port) || port->ip_receiver != space || port->ip_receiver_name != name || sq_port_slot(port)) {
		goto out_port;
	}

	imq_lock(&port->ip_messages);
	lck_spin_lock(&region->lock);

	if (!region->poisoned && region->free_slot != UINT32_MAX) {
		dtape_sq_slot_t* slot = &region->slots[region->free_slot];
		dsq_s_slot_t* sslot = &region->view.s->slots[slot->index];
		uint32_t rights = DSQ_RIGHT_RECEIVE | ((entry->ie_bits & MACH_PORT_TYPE_SEND) ? DSQ_RIGHT_SEND : 0);
		uint32_t epoch;

		sslot->name = name;
		sslot->qlimit = port->ip_messages.imq_qlimit;
		__atomic_store_n(&sslot->context, port->ip_context, __ATOMIC_RELAXED);
		sslot->close_reason = DSQ_CLOSE_NONE;
		__atomic_store_n(&sslot->gen, sslot->gen + 1, __ATOMIC_RELEASE);

		epoch = dsq_slot_open(&region->view, slot->index, port->ip_messages.imq_seqno);
		if (dsq_name_set(&region->view, name, slot->index, rights, epoch)) {
			region->free_slot = slot->next_free;
			slot->port = port;
			slot->name = name;
			slot->rights = rights;
			slot->tokens_published = 0;
			slot->tokens_taken = 0;
			__atomic_store_n(&port->ip_sq, slot, __ATOMIC_RELEASE);
		} else {
			// the name table is full: the port stays normal
			uint64_t h, made, d;
			dsq_close(&region->view, slot->index, &h, &made, &d);
		}
	}

	lck_spin_unlock(&region->lock);
	imq_unlock(&port->ip_messages);
out_port:
	ip_unlock(port);
out_space:
	is_read_unlock(space);
}

// takes the head node of a slot the server has taken over, for a kmsg; NULL if the node is not a valid one
static ipc_kmsg_t sq_node_to_kmsg(dtape_sq_slot_t* slot, ipc_port_t port, uint32_t index)
{
	dtape_sq_region_t* region = slot->region;
	dsq_node_t* shared = dsq_node(&region->view, index);
	dsq_node_t node;
	ipc_kmsg_t kmsg = IKM_NULL;

	// one copy: the task can't change what is validated afterwards
	memcpy(&node, shared, sizeof(node));

	if ((node.flags & DSQ_NODE_INLINE) && index < DSQ_TNODES) {
		const dtape_sq_history_entry_t* tokens = sq_history(region, node.aux);
		if (node.size >= DSQ_MSG_MIN && node.size <= DSQ_MSG_MAX) {
			kmsg = dtape_kmsg_from_shared(port, slot->name, node.msg, node.size,
			    (node.flags & DSQ_NODE_MADE_SEND) != 0, &tokens->sec_token, &tokens->audit_token);
		}
		if (!dsq_server_node_return(&region->view, index, SQ_ATTEMPTS)) {
			dtape_log_warning("%d: could not give a node back to the task", region->task->saved_pid);
		}
	} else if ((node.flags & DSQ_NODE_TOKEN) && index >= DSQ_TNODES) {
		if (node.aux == slot->tokens_taken) {
			kmsg = ipc_kmsg_dequeue(&slot->tokens);
			if (kmsg != IKM_NULL) {
				slot->tokens_taken++;
			}
		}
		if (region->snode_free_count < DSQ_SNODES) {
			region->snode_free[region->snode_free_count++] = (uint16_t) index;
		}
	}

	return kmsg;
}

// closes a slot without moving its queue (region locked). no publish or take succeeds afterwards;
// dtape_sq_port_leave_locked() moves the queue to the port later
static void sq_close_for_later(dtape_sq_slot_t* slot)
{
	dtape_sq_region_t* region = slot->region;
	dsq_q_slot_t* qslot = &region->view.q->slots[slot->index];
	uint64_t h, made, d;

	__atomic_store_n(&region->view.s->slots[slot->index].close_reason, DSQ_CLOSE_OTHER, __ATOMIC_RELEASE);
	dsq_close(&region->view, slot->index, &h, &made, &d);
	slot->closing = true;
	sq_wake(region, &qslot->head);
	sq_wake(region, &qslot->deq);
}

void dtape_sq_port_leave_locked(ipc_port_t port, uint32_t reason)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	ipc_mqueue_t mqueue = &port->ip_messages;
	dtape_sq_region_t* region;
	dsq_q_slot_t* qslot;
	uint16_t nodes[DSQ_NODES];
	uint64_t h, made, d;
	uint32_t len, found;
	bool corrupt = false;

	if (!slot) {
		return;
	}
	region = slot->region;
	qslot = &region->view.q->slots[slot->index];

	lck_spin_lock(&region->lock);

	// a receiver woken by the close reads the reason
	if (!slot->closing) {
		__atomic_store_n(&region->view.s->slots[slot->index].close_reason, reason, __ATOMIC_RELEASE);
	}
	dsq_close(&region->view, slot->index, &h, &made, &d);

	len = DSQ_LEN(h, d);
	if (len > DSQ_NODES) {
		corrupt = true;
		len = 0;
	}
	for (uint32_t i = 0; i < len; i++) {
		nodes[i] = DSQ_NONE;
	}
	found = dsq_collect(&region->view, slot->index, h, d, nodes);
	if (found != len) {
		corrupt = true;
	}

	// the queued messages go to the port's own queue, in order
	for (uint32_t i = 0; i < len; i++) {
		ipc_kmsg_t kmsg;
		if (nodes[i] == DSQ_NONE) {
			continue;
		}
		kmsg = sq_node_to_kmsg(slot, port, nodes[i]);
		if (kmsg == IKM_NULL) {
			corrupt = true;
			continue;
		}
		ipc_kmsg_enqueue(&mqueue->imq_messages, kmsg);
		mqueue->imq_msgcount++;
	}

	// tokens a damaged list lost (their nodes stay with the server until the region goes)
	for (ipc_kmsg_t kmsg; (kmsg = ipc_kmsg_dequeue(&slot->tokens)) != IKM_NULL;) {
		corrupt = true;
		ipc_kmsg_enqueue(&mqueue->imq_messages, kmsg);
		mqueue->imq_msgcount++;
	}

	mqueue->imq_seqno = DSQ_D_SEQNO(d);
	port->ip_mscount += (mach_port_mscount_t) made;

	if (corrupt) {
		sq_poison(region, "inconsistent queue");
	}

	sq_wake(region, &qslot->head);
	sq_wake(region, &qslot->deq);

	dsq_name_remove(&region->view, slot->name);
	slot->port = IP_NULL;
	slot->name = MACH_PORT_NULL;
	slot->rights = 0;
	slot->closing = false;
	__atomic_store_n(&port->ip_sq, NULL, __ATOMIC_RELEASE);
	slot->next_free = region->free_slot;
	region->free_slot = slot->index;

	lck_spin_unlock(&region->lock);
}

void dtape_sq_port_leave(ipc_port_t port, uint32_t reason)
{
	if (!sq_port_slot(port)) {
		return;
	}
	imq_lock(&port->ip_messages);
	dtape_sq_port_leave_locked(port, reason);
	imq_unlock(&port->ip_messages);
}

void dtape_sq_entry_modified(ipc_space_t space, mach_port_name_t name, ipc_entry_t entry)
{
	ipc_port_t port;
	dtape_sq_slot_t* slot;
	dtape_sq_region_t* region;
	uint32_t rights;

	// only send and receive rights name a port (an object being created has no bits yet and is no port in the mode)
	if (entry->ie_object == IO_NULL || (entry->ie_bits & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE)) == 0 ||
	    !io_active(entry->ie_object) || io_otype(entry->ie_object) != IOT_PORT) {
		return;
	}
	port = ip_object_to_port(entry->ie_object);
	slot = sq_port_slot(port);
	if (!slot) {
		return;
	}
	region = slot->region;
	// a name in another task's space (a send right to the port) is not the one the region describes
	if (region->task->xnu_task.itk_space != space) {
		return;
	}

	rights = ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) ? DSQ_RIGHT_RECEIVE : 0) |
	         ((entry->ie_bits & MACH_PORT_TYPE_SEND) ? DSQ_RIGHT_SEND : 0);

	lck_spin_lock(&region->lock);
	if (slot->port == port && slot->name == name && slot->rights != rights && !slot->closing) {
		// the task's lookups see the new rights together with the next epoch, and a publish made with the
		// old rights succeeds only before the epoch changes, i.e. before this call returns
		uint64_t h = dsq_load(&region->view.q->slots[slot->index].head);
		uint32_t epoch = (DSQ_H_EPOCH(h) + 1) & 0xffff;
		uint32_t new_epoch;

		if (!dsq_name_set(&region->view, name, slot->index, rights, epoch) ||
		    !dsq_slot_bump_epoch(&region->view, slot->index, SQ_ATTEMPTS, &new_epoch) ||
		    new_epoch != epoch) {
			// the task kept the head busy: close the slot instead. the caller may hold the port lock,
			// so the queue moves to the port the next time the server has the port locked
			sq_close_for_later(slot);
		}
		slot->rights = rights;
	}
	lck_spin_unlock(&region->lock);
}

void dtape_sq_port_context_changed(ipc_port_t port)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	if (slot) {
		dsq_s_slot_t* sslot = &slot->region->view.s->slots[slot->index];
		__atomic_store_n(&sslot->context, port->ip_context, __ATOMIC_RELEASE);
	}
}

void dtape_sq_port_qlimit_changed(ipc_port_t port)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	if (slot) {
		dtape_sq_region_t* region = slot->region;
		dsq_s_slot_t* sslot = &region->view.s->slots[slot->index];
		__atomic_store_n(&sslot->qlimit, port->ip_messages.imq_qlimit, __ATOMIC_RELEASE);
		// senders waiting for room look again, as XNU wakes full waiters when the limit is raised
		sq_wake(region, &region->view.q->slots[slot->index].deq);
	}
}

boolean_t dtape_sq_mqueue_send(ipc_port_t port, ipc_kmsg_t kmsg, mach_msg_option_t option,
    mach_msg_timeout_t send_timeout, mach_msg_return_t* mrp)
{
	ipc_mqueue_t mqueue = &port->ip_messages;
	dtape_sq_slot_t* slot = sq_port_slot(port);
	dtape_sq_region_t* region;
	dsq_q_slot_t* qslot;
	dsq_node_t* node;
	uint64_t h, d;
	uint32_t len, index;
	boolean_t full, kernel_full;
	int result;

	if (!slot) {
		return FALSE;
	}
	region = slot->region;
	qslot = &region->view.q->slots[slot->index];

	lck_spin_lock(&region->lock);

	if (region->poisoned || slot->closing) {
		goto leave;
	}

	h = dsq_load(&qslot->head);
	d = dsq_load(&qslot->deq);
	if (DSQ_IS_CLOSED(h) || DSQ_IS_CLOSED(d)) {
		// only the server closes a slot
		if (!slot->closing) {
			sq_poison(region, "a queue was closed by the task");
		}
		goto leave;
	}

	// the same rule as ipc_mqueue_send(), with the shared queue's length
	len = DSQ_LEN(h, d);
	full = len >= mqueue->imq_qlimit;
	kernel_full = len >= MACH_PORT_QLIMIT_KERNEL;
	if (full && !(!kernel_full && ((option & MACH_SEND_ALWAYS) ||
	    MACH_MSGH_BITS_REMOTE(kmsg->ikm_header->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE))) {
		if ((option & MACH_SEND_TIMEOUT) && send_timeout == 0) {
			*mrp = MACH_SEND_TIMED_OUT;
			goto done;
		}
		if (kernel_full) {
			*mrp = MACH_SEND_NO_BUFFER;
			goto done;
		}
		// the sender has to wait for room: that is done by the port's own queue
		goto leave;
	}

	if (region->snode_free_count == 0) {
		goto leave;
	}
	index = region->snode_free[--region->snode_free_count];
	node = dsq_node(&region->view, index);

	{
		mach_msg_size_t size = ipc_kmsg_copyout_size(kmsg, port->ip_receiver->is_task->map);
		node->flags = DSQ_NODE_TOKEN;
		node->size = (uint16_t) (size > 0xffff ? 0xffff : size);
		node->aux = slot->tokens_published;
	}

	ipc_kmsg_enqueue(&slot->tokens, kmsg);
	result = dsq_publish(&region->view, slot->index, index, DSQ_EPOCH_ANY, UINT32_MAX, false, SQ_ATTEMPTS, NULL);
	if (result != DSQ_OK) {
		ipc_kmsg_rmqueue(&slot->tokens, kmsg);
		region->snode_free[region->snode_free_count++] = (uint16_t) index;
		goto leave;
	}
	slot->tokens_published++;

	if (__atomic_load_n(&qslot->rcv_waiters, __ATOMIC_ACQUIRE) != 0) {
		// one message, one receiver
		sq_wake_count(region, &qslot->head, 1);
	}

	current_task()->messages_sent++;
	*mrp = MACH_MSG_SUCCESS;

done:
	lck_spin_unlock(&region->lock);
	imq_unlock(mqueue);
	ip_unlock(port);
	return TRUE;

leave:
	lck_spin_unlock(&region->lock);
	dtape_sq_port_leave_locked(port, DSQ_CLOSE_OTHER);
	return FALSE;
}

boolean_t dtape_sq_mqueue_receive(ipc_mqueue_t mqueue, mach_msg_option_t option, mach_msg_size_t max_size,
    mach_msg_timeout_t rcv_timeout, thread_t thread)
{
	ipc_port_t port;
	dtape_sq_slot_t* slot;
	dtape_sq_region_t* region;
	dsq_q_slot_t* qslot;
	dtape_thread_t* dthread = dtape_thread_for_xnu_thread(thread);
	boolean_t handled = FALSE;
	bool local_wait = false;

	// the request applies to this receive only, whichever way it goes
	if (dthread) {
		local_wait = dthread->sq_local_wait;
		dthread->sq_local_wait = false;
	}

	if (imq_is_set(mqueue)) {
		return FALSE;
	}
	port = ip_from_mq(mqueue);
	if (!sq_port_slot(port)) {
		return FALSE;
	}

	ip_lock(port);
	imq_lock(mqueue);

	slot = sq_port_slot(port);
	if (!slot || !ip_active(port)) {
		goto out;
	}
	region = slot->region;
	qslot = &region->view.q->slots[slot->index];

	if ((option & MACH_PEEK_MSG) || region->poisoned || slot->closing) {
		goto leave;
	}

	for (uint32_t attempt = 0; attempt < SQ_ATTEMPTS; attempt++) {
		uint64_t d;
		uint32_t index;
		int result = dsq_head(&region->view, slot->index, &d, &index);

		if (result == DSQ_RETRY) {
			continue;
		}
		if (result == DSQ_EMPTY) {
			if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0) {
				// XNU's own path finds the (empty) port queue and times out
				goto out;
			}
			if (local_wait) {
				// the task waits for the queue itself (see the mach_msg_sq_receive call)
				dthread->sq_local_wait_result = true;
				thread->ith_kmsg = IKM_NULL;
				thread->ith_seqno = 0;
				thread->ith_state = MACH_RCV_TIMED_OUT;
				handled = TRUE;
				goto out;
			}
			// a receive that would block in the server: the port leaves the mode and the receive blocks normally
			goto leave;
		}
		if (result != DSQ_OK) {
			lck_spin_lock(&region->lock);
			if (!(result == DSQ_CLOSED_Q && slot->closing)) {
				sq_poison(region, result == DSQ_CLOSED_Q ? "a queue was closed by the task" : "inconsistent queue");
			}
			lck_spin_unlock(&region->lock);
			goto leave;
		}

		// the node is queued and doesn't change while it is: its fields are valid if deq is still `d`
		dsq_node_t* node = dsq_node(&region->view, index);
		uint32_t flags = __atomic_load_n(&node->flags, __ATOMIC_RELAXED);
		mach_msg_size_t msize;

		lck_spin_lock(&region->lock);
		if ((flags & DSQ_NODE_TOKEN) && index >= DSQ_TNODES) {
			ipc_kmsg_t first = ipc_kmsg_queue_first(&slot->tokens);
			if (first == IKM_NULL) {
				sq_poison(region, "a token without a message");
				lck_spin_unlock(&region->lock);
				goto leave;
			}
			msize = ipc_kmsg_copyout_size(first, thread->map);
		} else if ((flags & DSQ_NODE_INLINE) && index < DSQ_TNODES) {
			msize = __atomic_load_n(&node->size, __ATOMIC_RELAXED);
		} else {
			lck_spin_unlock(&region->lock);
			if (dsq_load(&qslot->deq) != d) {
				continue;
			}
			lck_spin_lock(&region->lock);
			sq_poison(region, "a node of an unknown kind");
			lck_spin_unlock(&region->lock);
			goto leave;
		}
		lck_spin_unlock(&region->lock);

		if (dsq_load(&qslot->deq) != d) {
			continue;
		}

		boolean_t too_large = msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size;
		if (too_large && (option & MACH_RCV_LARGE)) {
			// left queued, as ipc_mqueue_select_on_thread() does
			thread->ith_receiver_name = mqueue->imq_receiver_name;
			thread->ith_kmsg = IKM_NULL;
			thread->ith_msize = msize;
			thread->ith_seqno = 0;
			thread->ith_state = MACH_RCV_TOO_LARGE;
			handled = TRUE;
			goto out;
		}

		if (!dsq_take(&region->view, slot->index, d)) {
			continue;
		}

		lck_spin_lock(&region->lock);
		ipc_kmsg_t kmsg = sq_node_to_kmsg(slot, port, index);
		if (kmsg == IKM_NULL) {
			sq_poison(region, "an invalid message");
			lck_spin_unlock(&region->lock);
			goto leave;
		}
		lck_spin_unlock(&region->lock);

		if (__atomic_load_n(&qslot->snd_waiters, __ATOMIC_ACQUIRE) != 0) {
			sq_wake(region, &qslot->deq);
		}

		// the message as built is what counts (the task could have changed its node meanwhile)
		msize = ipc_kmsg_copyout_size(kmsg, thread->map);
		too_large = msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size;

		thread->ith_kmsg = kmsg;
		thread->ith_seqno = DSQ_D_SEQNO(d);
		thread->ith_msize = msize;
		thread->ith_state = too_large ? MACH_RCV_TOO_LARGE : MACH_MSG_SUCCESS;
		current_task()->messages_received++;
		handled = TRUE;
		goto out;
	}

leave:
	dtape_sq_port_leave_locked(port, DSQ_CLOSE_OTHER);
out:
	imq_unlock(mqueue);
	ip_unlock(port);
	return handled;
}

void dtape_sq_port_status(ipc_port_t port, mach_port_status_t* status)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	dsq_q_slot_t* qslot;
	uint64_t h, made, d;
	uint32_t len, tokens;

	if (!slot) {
		return;
	}
	qslot = &slot->region->view.q->slots[slot->index];

	// a snapshot of the words; nothing changes
	d = dsq_load(&qslot->deq);
	h = dsq_load(&qslot->head);
	made = __atomic_load_n(&qslot->made, __ATOMIC_ACQUIRE);
	tokens = slot->tokens_published - slot->tokens_taken;
	len = DSQ_LEN(h, d);
	if (len > port->ip_messages.imq_qlimit + tokens) {
		len = port->ip_messages.imq_qlimit + tokens;
	}

	status->mps_msgcount += len;
	status->mps_seqno = DSQ_D_SEQNO(d);
	status->mps_mscount += (mach_port_mscount_t) made;
	// a queued message of the task's own holds a send right
	if (len > tokens) {
		status->mps_srights = TRUE;
	}
}

mach_port_msgcount_t dtape_sq_port_message_count(ipc_port_t port)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	mach_port_msgcount_t count = port->ip_messages.imq_msgcount;

	if (slot) {
		dsq_q_slot_t* qslot = &slot->region->view.q->slots[slot->index];
		uint64_t d = dsq_load(&qslot->deq);
		uint64_t h = dsq_load(&qslot->head);
		uint32_t len = DSQ_LEN(h, d);
		count += (len > DSQ_NODES) ? DSQ_NODES : len;
	}
	return count;
}

int dtape_mach_msg_sq_receive(uint64_t msg, int32_t option, uint32_t rcv_size, uint32_t rcv_name, uint32_t timeout)
{
	dtape_thread_t* dthread = dtape_thread_for_xnu_thread(current_thread());
	struct mach_msg_overwrite_trap_args args = {
		.msg = msg,
		.option = option & ~MACH_SEND_MSG,
		.send_size = 0,
		.rcv_size = rcv_size,
		.rcv_name = rcv_name,
		.timeout = timeout,
		.priority = 0,
		.rcv_msg = 0,
	};
	kern_return_t kr;

	dthread->sq_local_wait = true;
	dthread->sq_local_wait_result = false;

	kr = mach_msg_overwrite_trap(&args);

	dthread->sq_local_wait = false;
	if (dthread->sq_local_wait_result) {
		dthread->sq_local_wait_result = false;
		return DSQ_RCV_WAIT_LOCALLY;
	}
	return kr;
}
