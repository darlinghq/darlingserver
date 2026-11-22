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
#include <ipc/ipc_pset.h>
#include <ipc/ipc_mqueue.h>
#include <kern/waitq.h>
#include <ipc/ipc_kmsg.h>
#include <mach/mach_traps.h>

#include <stdlib.h>

// bounds of the server's loops over words the task can also change
#define SQ_ATTEMPTS 64

typedef struct dtape_sq_slot {
	struct dtape_sq_region* region;
	uint32_t index;
	uint32_t next_free;
	ipc_port_t port;            // NULL while the slot is free (and for a set slot)
	ipc_pset_t pset;            // a set slot: its port set; NULL otherwise
	// a member port: the slot of the set it is in the mode with (the set's bitmap in S says the same)
	struct dtape_sq_slot* set;
	mach_port_name_t name;      // the receive right's name
	uint32_t rights;            // DSQ_RIGHT_* recorded in the name table
	uint32_t tokens_published;  // token ids: published in id order, and taken in that order too
	uint32_t tokens_taken;
	// closed, but its queue has not been moved to the port yet: whatever next has the port locked does that
	bool closing;
	// the words dsq_close() returned for that close (the only record of them; see mach-sq.h)
	uint64_t closed_head;
	uint64_t closed_deq;
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

static inline dtape_sq_slot_t* sq_pset_slot(ipc_pset_t pset)
{
	return __atomic_load_n(&pset->ips_sq, __ATOMIC_ACQUIRE);
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
		if ((slot->port != IP_NULL || slot->pset != NULL) && !slot->closing) {
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
		if (region->slots[i].port != IP_NULL || region->slots[i].pset != NULL) {
			dtape_log_error("%d: a port is still in shared-queue mode after its space was terminated", task->saved_pid);
		}
	}

	dtape_hooks->sq_region_release(region->view.s, DSQ_S_SIZE, region->view.q, DSQ_Q_SIZE);
	lck_spin_destroy(&region->lock, LCK_GRP_NULL);
	free(region);
}

// mk_timer ports (kernel objects whose only message is the kernel's expiry message, with one preallocated kmsg) take
// part: they are the timer of CF's run loops, which waits for it in a set with its other ports
static bool sq_port_is_timer(ipc_port_t port)
{
	return ip_is_kobject(port) && ip_kotype(port) == IKOT_TIMER;
}

static bool sq_port_eligible(ipc_port_t port)
{
	return ip_active(port) &&
	       (!ip_is_kobject(port) || sq_port_is_timer(port)) &&
	       !port->ip_specialreply &&
	       !port->ip_impdonation &&
	       !port->ip_tempowner &&
	       (!IP_PREALLOC(port) || sq_port_is_timer(port)) &&
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
		uint32_t rights = DSQ_RIGHT_RECEIVE | ((entry->ie_bits & MACH_PORT_TYPE_SEND) ? DSQ_RIGHT_SEND : 0) |
		                  (sq_port_is_timer(port) ? DSQ_RIGHT_NOSEND : 0);
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
			slot->pset = NULL;
			slot->set = NULL;
			__atomic_store_n(&port->ip_sq, slot, __ATOMIC_RELEASE);
		} else {
			// the name table is full: the port stays normal
			uint64_t h, d;
			dsq_close(&region->view, slot->index, &h, &d);
		}
	}

	lck_spin_unlock(&region->lock);
	imq_unlock(&port->ip_messages);
out_port:
	ip_unlock(port);
out_space:
	is_read_unlock(space);
}

// whether a node (the server's copy of it) is a MAKE_SEND message of the task: the ones the port's
// make-send count has to include
static inline bool sq_node_made_send(const dsq_node_t* node, uint32_t index)
{
	return index < DSQ_TNODES && (node->flags & DSQ_NODE_INLINE) && (node->flags & DSQ_NODE_MADE_SEND);
}

// makes a kmsg of a node of a slot the server has taken (`node` is the server's one copy of node `index`:
// the task can't change what is validated afterwards); NULL if the node is not a valid one
static ipc_kmsg_t sq_node_to_kmsg(dtape_sq_slot_t* slot, ipc_port_t port, uint32_t index, const dsq_node_t* copy)
{
	dtape_sq_region_t* region = slot->region;
	const dsq_node_t node = *copy;
	ipc_kmsg_t kmsg = IKM_NULL;

	if ((node.flags & DSQ_NODE_INLINE) && index < DSQ_TNODES) {
		const dtape_sq_history_entry_t* tokens = sq_history(region, node.aux);
		if (node.size >= DSQ_MSG_MIN && node.size <= DSQ_MSG_MAX) {
			kmsg = dtape_kmsg_from_shared(port, slot->name, node.msg, node.size,
			    sq_node_made_send(&node, index), &tokens->sec_token, &tokens->audit_token);
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

	__atomic_store_n(&region->view.s->slots[slot->index].close_reason, DSQ_CLOSE_OTHER, __ATOMIC_RELEASE);
	dsq_close(&region->view, slot->index, &slot->closed_head, &slot->closed_deq);
	slot->closing = true;
	sq_wake(region, &qslot->head);
	sq_wake(region, &qslot->deq);
}

// ---- port sets ------------------------------------------------------------------------------------------

// `member` is no longer a member of its set (region locked). The set's bitmap, the member's S fields and the
// server's link are cleared; the set's receivers are woken.
static void sq_member_unlink_locked(dtape_sq_slot_t* member)
{
	dtape_sq_slot_t* set = member->set;
	dtape_sq_region_t* region = member->region;

	if (!set) {
		return;
	}
	(void) dsq_set_member_remove(&region->view, set->index, member->index);
	member->set = NULL;
}

// takes the set slot and every member's slot out of the mode (region locked): a set the task can't receive on
// through the region can't have members whose queues are in it. Only closes; the queues of the members move to
// their ports when each next gets a server operation, and all of them when the server next receives on the set
// (sq_set_drain_members()).
static void sq_set_close_all_for_later(dtape_sq_slot_t* set)
{
	dtape_sq_region_t* region = set->region;
	dsq_q_slot_t* qslot = &region->view.q->slots[set->index];

	if (set->closing) {
		return;
	}
	__atomic_store_n(&region->view.s->slots[set->index].close_reason, DSQ_CLOSE_OTHER, __ATOMIC_RELEASE);
	dsq_close(&region->view, set->index, &set->closed_head, &set->closed_deq);
	set->closing = true;
	sq_wake(region, (uint64_t*) &qslot->setword);

	for (uint32_t w = 0; w < DSQ_SET_WORDS; w++) {
		uint32_t bits = __atomic_load_n(&region->view.s->members[set->index][w], __ATOMIC_ACQUIRE);
		while (bits != 0) {
			dtape_sq_slot_t* member = &region->slots[w * 32 + (uint32_t) __builtin_ctz(bits)];
			bits &= bits - 1;
			if (member->port != IP_NULL && !member->closing) {
				sq_close_for_later(member);
			}
		}
	}
}

// the set slot is no longer needed (region locked): free it
static void sq_set_finalize_locked(dtape_sq_slot_t* set)
{
	dtape_sq_region_t* region = set->region;

	for (uint32_t w = 0; w < DSQ_SET_WORDS; w++) {
		uint32_t bits = __atomic_load_n(&region->view.s->members[set->index][w], __ATOMIC_ACQUIRE);
		while (bits != 0) {
			dtape_sq_slot_t* member = &region->slots[w * 32 + (uint32_t) __builtin_ctz(bits)];
			bits &= bits - 1;
			if (member->set == set) {
				sq_member_unlink_locked(member);
			}
		}
	}
	if (!set->closing) {
		uint64_t h, d;
		__atomic_store_n(&region->view.s->slots[set->index].close_reason, DSQ_CLOSE_DESTROYED, __ATOMIC_RELEASE);
		dsq_close(&region->view, set->index, &h, &d);
		sq_wake(region, (uint64_t*) &region->view.q->slots[set->index].setword);
	}
	dsq_name_remove(&region->view, set->name);
	if (set->pset != NULL) {
		__atomic_store_n(&set->pset->ips_sq, NULL, __ATOMIC_RELEASE);
	}
	set->pset = NULL;
	set->name = MACH_PORT_NULL;
	set->rights = 0;
	set->closing = false;
	set->next_free = region->free_slot;
	region->free_slot = set->index;
}

void dtape_sq_port_leave_locked(ipc_port_t port, uint32_t reason)
{
	dtape_sq_slot_t* slot = sq_port_slot(port);
	ipc_mqueue_t mqueue = &port->ip_messages;
	dtape_sq_region_t* region;
	dsq_q_slot_t* qslot;
	uint16_t nodes[DSQ_NODES];
	uint64_t h, d;
	uint32_t len, found;
	mach_port_mscount_t made;
	bool corrupt = false;

	if (!slot) {
		return;
	}
	region = slot->region;
	qslot = &region->view.q->slots[slot->index];

	lck_spin_lock(&region->lock);

	// a member of a set: the set can't be received on through the region without it, unless the port is
	// only going away (destroyed, or its receive right moves), which is a removal from the set
	if (slot->set != NULL && reason != DSQ_CLOSE_DESTROYED && reason != DSQ_CLOSE_MOVED) {
		sq_set_close_all_for_later(slot->set);
	}

	// a receiver woken by the close reads the reason
	if (slot->closing) {
		h = slot->closed_head;
		d = slot->closed_deq;
	} else {
		__atomic_store_n(&region->view.s->slots[slot->index].close_reason, reason, __ATOMIC_RELEASE);
		dsq_close(&region->view, slot->index, &h, &d);
	}
	// the MAKE_SEND messages dequeued so far; the ones still queued are added below
	made = DSQ_D_MADE(d);

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
		dsq_node_t node;
		if (nodes[i] == DSQ_NONE) {
			continue;
		}
		memcpy(&node, dsq_node(&region->view, nodes[i]), sizeof(node));
		if (sq_node_made_send(&node, nodes[i])) {
			made++;
		}
		kmsg = sq_node_to_kmsg(slot, port, nodes[i], &node);
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

	// what the port's counts are once the queue is its own again: every message dequeued from the shared
	// queue took a seqno, and every MAKE_SEND message published counts, dequeued or still queued
	mqueue->imq_seqno = dsq_seqno(&region->view, slot->index, d);
	port->ip_mscount += made;

	if (corrupt) {
		sq_poison(region, "inconsistent queue");
	}

	sq_wake(region, &qslot->head);
	sq_wake(region, &qslot->deq);

	sq_member_unlink_locked(slot);
	dsq_name_remove(&region->view, slot->name);
	slot->port = IP_NULL;
	slot->name = MACH_PORT_NULL;
	slot->rights = 0;
	slot->closing = false;
	__atomic_store_n(&port->ip_sq, NULL, __ATOMIC_RELEASE);
	slot->next_free = region->free_slot;
	region->free_slot = slot->index;

	lck_spin_unlock(&region->lock);

	if (len > 0 && port->ip_in_pset != 0) {
		// the port is in sets of XNU's: its messages are in its queue now, and the sets have to know (the
		// port is posted to them, as ipc_mqueue_post() does when a message arrives)
		uint64_t reserved_prepost = 0;
		spl_t th_spl;
		thread_t th = waitq_wakeup64_identify_locked(&mqueue->imq_wait_queue, IPC_MQUEUE_RECEIVE, THREAD_AWAKENED,
		    &th_spl, &reserved_prepost, WAITQ_ALL_PRIORITIES, WAITQ_KEEP_LOCKED);
		if (th != THREAD_NULL) {
			// nothing waits on a port that was in the mode
			thread_unlock(th);
			splx(th_spl);
		}
	}
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

// ---- port sets ------------------------------------------------------------------------------------------

void dtape_sq_set_created(ipc_space_t space, mach_port_name_t name)
{
	task_t xtask = current_task();
	dtape_task_t* task;
	dtape_sq_region_t* region;
	ipc_entry_t entry;
	ipc_pset_t pset;

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
	if (entry == IE_NULL || (entry->ie_bits & MACH_PORT_TYPE_PORT_SET) == 0) {
		goto out_space;
	}
	pset = ips_object_to_pset(entry->ie_object);

	ips_lock(pset);
	if (!ips_active(pset) || sq_pset_slot(pset)) {
		goto out_pset;
	}

	lck_spin_lock(&region->lock);
	if (!region->poisoned && region->free_slot != UINT32_MAX) {
		dtape_sq_slot_t* slot = &region->slots[region->free_slot];
		dsq_s_slot_t* sslot = &region->view.s->slots[slot->index];
		uint32_t rights = DSQ_RIGHT_RECEIVE | DSQ_RIGHT_SET;
		uint32_t epoch;

		sslot->name = name;
		sslot->qlimit = 0;
		__atomic_store_n(&sslot->context, 0, __ATOMIC_RELAXED);
		sslot->close_reason = DSQ_CLOSE_NONE;
		__atomic_store_n(&sslot->gen, sslot->gen + 1, __ATOMIC_RELEASE);

		epoch = dsq_slot_open(&region->view, slot->index, 0);
		__atomic_store_n(&sslot->kind, (uint16_t) DSQ_KIND_SET, __ATOMIC_RELEASE);
		if (dsq_name_set(&region->view, name, slot->index, rights, epoch)) {
			region->free_slot = slot->next_free;
			slot->port = IP_NULL;
			slot->pset = pset;
			slot->set = NULL;
			slot->name = name;
			slot->rights = rights;
			slot->tokens_published = 0;
			slot->tokens_taken = 0;
			__atomic_store_n(&pset->ips_sq, slot, __ATOMIC_RELEASE);
		} else {
			// the name table is full: the set stays normal
			uint64_t h, d;
			dsq_close(&region->view, slot->index, &h, &d);
		}
	}
	lck_spin_unlock(&region->lock);
out_pset:
	ips_unlock(pset);
out_space:
	is_read_unlock(space);
}

// `port` and `pset` locked (ipc_pset_add(), before the link is made)
void dtape_sq_pset_add(ipc_pset_t pset, ipc_port_t port)
{
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);
	dtape_sq_slot_t* mslot = sq_port_slot(port);

	if (!pslot && !mslot) {
		return;
	}

	if (pslot && mslot && pslot->region == mslot->region) {
		dtape_sq_region_t* region = pslot->region;
		bool joined = false;

		lck_spin_lock(&region->lock);
		if (mslot->set == pslot) {
			// already a member: XNU answers that
			lck_spin_unlock(&region->lock);
			return;
		}
		// not a member of another set, and nothing is leaving the mode. (a thread that waits on the port itself
		// goes on doing so: the port's own word changes at every publish too)
		if (!region->poisoned && !pslot->closing && !mslot->closing && mslot->set == NULL) {
			dsq_set_member_add(&region->view, pslot->index, mslot->index, dsq_stamp_next(&region->view));
			mslot->set = pslot;
			joined = true;
		}
		lck_spin_unlock(&region->lock);
		if (joined) {
			// a receiver that is waiting looks again: the port may have messages
			if (__atomic_load_n(&region->view.q->slots[pslot->index].rcv_waiters, __ATOMIC_ACQUIRE) != 0) {
				sq_wake(region, (uint64_t*) &region->view.q->slots[pslot->index].setword);
			}
			return;
		}
	}

	// every other combination: a set can only be received on through the region if all its members are in it
	if (mslot) {
		dtape_sq_port_leave(port, DSQ_CLOSE_OTHER);
	}
	if (pslot) {
		lck_spin_lock(&pslot->region->lock);
		sq_set_close_all_for_later(pslot);
		lck_spin_unlock(&pslot->region->lock);
	}
}

// `port` leaves its set `pslot` (the port and the set locked)
static void sq_pset_member_removed(ipc_port_t port, dtape_sq_slot_t* mslot, dtape_sq_slot_t* pslot)
{
	dtape_sq_region_t* region = mslot->region;
	bool quiet;

	lck_spin_lock(&region->lock);
	if (mslot->set != pslot) {
		lck_spin_unlock(&region->lock);
		return;
	}
	quiet = dsq_set_member_remove(&region->view, pslot->index, mslot->index);
	mslot->set = NULL;
	lck_spin_unlock(&region->lock);

	if (!quiet) {
		// a thread of the task was looking for a message and may still take one from this port: the port leaves
		// the mode, which makes such a take fail
		dtape_sq_port_leave(port, DSQ_CLOSE_OTHER);
	}
}

void dtape_sq_pset_remove(ipc_pset_t pset, ipc_port_t port)
{
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);
	dtape_sq_slot_t* mslot = sq_port_slot(port);

	if (pslot && mslot) {
		sq_pset_member_removed(port, mslot, pslot);
	}
}

void dtape_sq_port_removed_from_sets(ipc_port_t port)
{
	dtape_sq_slot_t* mslot = sq_port_slot(port);
	dtape_sq_slot_t* pslot;

	if (!mslot) {
		return;
	}
	lck_spin_lock(&mslot->region->lock);
	pslot = mslot->set;
	lck_spin_unlock(&mslot->region->lock);
	if (pslot) {
		sq_pset_member_removed(port, mslot, pslot);
	}
}

void dtape_sq_pset_destroyed(ipc_pset_t pset)
{
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);

	if (!pslot) {
		return;
	}
	// the members stay in the mode as plain ports
	lck_spin_lock(&pslot->region->lock);
	sq_set_finalize_locked(pslot);
	lck_spin_unlock(&pslot->region->lock);
}

// the priority of the oldest message in a closed member's queue (0 if it has none)
static uint32_t sq_member_closed_prio(dtape_sq_region_t* region, dtape_sq_slot_t* member)
{
	uint16_t nodes[DSQ_NODES];
	uint32_t len = DSQ_LEN(member->closed_head, member->closed_deq);
	uint32_t floor = __atomic_load_n(&region->view.s->slots[member->index].floor, __ATOMIC_RELAXED);

	if (!member->closing || len == 0 || len > DSQ_NODES) {
		return 0;
	}
	for (uint32_t i = 0; i < len; i++) {
		nodes[i] = DSQ_NONE;
	}
	if (dsq_collect(&region->view, member->index, member->closed_head, member->closed_deq, nodes) == 0 ||
	    nodes[0] == DSQ_NONE) {
		return floor;
	}
	uint32_t run = dsq_node(&region->view, nodes[0])->run;
	return (run == 0 || (int32_t) (run - floor) < 0) ? floor : run;
}

// Moves the queues of the members of a set that has left the mode to their ports (the server holds no lock of any
// port or set), the member that was ready longest first, so that XNU's own receive on the set finds the members
// preposted in the order the shared queue would have served them. Then the set's slot is free.
static void sq_set_drain_members(ipc_pset_t pset)
{
	struct entry {
		ipc_port_t port;
		dtape_sq_slot_t* slot;
		uint32_t prio;
	} members[DSQ_SLOTS];
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);
	dtape_sq_region_t* region;
	uint32_t count = 0;

	if (!pslot) {
		return;
	}
	region = pslot->region;

	lck_spin_lock(&region->lock);
	if (!pslot->closing) {
		lck_spin_unlock(&region->lock);
		return;
	}
	for (uint32_t w = 0; w < DSQ_SET_WORDS; w++) {
		uint32_t bits = __atomic_load_n(&region->view.s->members[pslot->index][w], __ATOMIC_ACQUIRE);
		while (bits != 0) {
			dtape_sq_slot_t* member = &region->slots[w * 32 + (uint32_t) __builtin_ctz(bits)];
			bits &= bits - 1;
			if (member->port != IP_NULL) {
				ip_reference(member->port);
				members[count].port = member->port;
				members[count].slot = member;
				members[count].prio = sq_member_closed_prio(region, member);
				count++;
			}
		}
	}
	lck_spin_unlock(&region->lock);

	// insertion sort, by priority (wrapping compare)
	for (uint32_t i = 1; i < count; i++) {
		struct entry e = members[i];
		uint32_t k = i;
		while (k > 0 && (int32_t) (e.prio - members[k - 1].prio) < 0) {
			members[k] = members[k - 1];
			k--;
		}
		members[k] = e;
	}

	for (uint32_t i = 0; i < count; i++) {
		ipc_port_t port = members[i].port;
		ip_lock(port);
		imq_lock(&port->ip_messages);
		if (sq_port_slot(port) == members[i].slot) {
			dtape_sq_port_leave_locked(port, DSQ_CLOSE_OTHER);
		}
		imq_unlock(&port->ip_messages);
		ip_unlock(port);
		ip_release(port);
	}

	lck_spin_lock(&region->lock);
	if (sq_pset_slot(pset) == pslot && pslot->closing) {
		sq_set_finalize_locked(pslot);
	}
	lck_spin_unlock(&region->lock);
}

void dtape_sq_pset_leave(ipc_pset_t pset)
{
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);

	if (!pslot) {
		return;
	}
	lck_spin_lock(&pslot->region->lock);
	sq_set_close_all_for_later(pslot);
	lck_spin_unlock(&pslot->region->lock);
	sq_set_drain_members(pset);
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
	// not a right: how the port is used (mk_timer)
	rights |= slot->rights & DSQ_RIGHT_NOSEND;
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
	uint32_t len, index, set = DSQ_NONE;
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

	d = dsq_load(&qslot->deq);
	h = dsq_load(&qslot->head);
	if (DSQ_IS_CLOSED(h)) {
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
	result = dsq_publish(&region->view, slot->index, index, DSQ_EPOCH_ANY, UINT32_MAX, SQ_ATTEMPTS, NULL, &set);
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
	if (set != DSQ_NONE && __atomic_load_n(&region->view.q->slots[set].rcv_waiters, __ATOMIC_ACQUIRE) != 0) {
		sq_wake_count(region, (uint64_t*) &region->view.q->slots[set].setword, 1);
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

enum {
	SQ_R_HANDLED, // the thread's receive state is set
	SQ_R_RETRY,   // the queue changed under the receive: look again
	SQ_R_LEAVE,   // the queue (or its set) leaves the mode
};

// Receives for `thread` the node `index`, which was the head of the queue of `slot` when its deq word was `d`.
// A receive on a set passes the pick (and the set's slot): the take then also needs the port to still be a member.
// The port and its mqueue are locked.
static int sq_receive_node(dtape_sq_slot_t* slot, ipc_port_t port, const dsq_set_pick_t* pick, uint32_t set,
    uint64_t d, uint32_t index, mach_msg_option_t option, mach_msg_size_t max_size, thread_t thread)
{
	ipc_mqueue_t mqueue = &port->ip_messages;
	dtape_sq_region_t* region = slot->region;
	dsq_q_slot_t* qslot = &region->view.q->slots[slot->index];
	dsq_node_t node;
	uint32_t flags;
	mach_msg_size_t msize;
	uint32_t seqno;
	boolean_t too_large;
	bool taken;

	// the node is queued and doesn't change while it is: the copy is valid if deq is still `d` afterwards, and
	// it is all the server uses (what it counts is what it receives)
	memcpy(&node, dsq_node(&region->view, index), sizeof(node));
	flags = node.flags;

	lck_spin_lock(&region->lock);
	if ((flags & DSQ_NODE_TOKEN) && index >= DSQ_TNODES) {
		ipc_kmsg_t first = ipc_kmsg_queue_first(&slot->tokens);
		if (first == IKM_NULL) {
			sq_poison(region, "a token without a message");
			lck_spin_unlock(&region->lock);
			return SQ_R_LEAVE;
		}
		msize = ipc_kmsg_copyout_size(first, thread->map);
	} else if ((flags & DSQ_NODE_INLINE) && index < DSQ_TNODES) {
		msize = node.size;
	} else {
		lck_spin_unlock(&region->lock);
		if (dsq_load(&qslot->deq) != d) {
			return SQ_R_RETRY;
		}
		lck_spin_lock(&region->lock);
		sq_poison(region, "a node of an unknown kind");
		lck_spin_unlock(&region->lock);
		return SQ_R_LEAVE;
	}
	lck_spin_unlock(&region->lock);

	if (dsq_load(&qslot->deq) != d) {
		return SQ_R_RETRY;
	}

	too_large = msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size;
	if (too_large && (option & MACH_RCV_LARGE)) {
		// left queued, as ipc_mqueue_select_on_thread() does; the receiver learns the member's name
		thread->ith_receiver_name = mqueue->imq_receiver_name;
		thread->ith_kmsg = IKM_NULL;
		thread->ith_msize = msize;
		thread->ith_seqno = 0;
		thread->ith_state = MACH_RCV_TOO_LARGE;
		return SQ_R_HANDLED;
	}

	if (pick != NULL) {
		taken = dsq_set_take(&region->view, set, pick, sq_node_made_send(&node, index), &seqno);
	} else {
		taken = dsq_take(&region->view, slot->index, d, sq_node_made_send(&node, index), &seqno);
	}
	if (!taken) {
		return SQ_R_RETRY;
	}

	lck_spin_lock(&region->lock);
	ipc_kmsg_t kmsg = sq_node_to_kmsg(slot, port, index, &node);
	if (kmsg == IKM_NULL) {
		sq_poison(region, "an invalid message");
		lck_spin_unlock(&region->lock);
		return SQ_R_LEAVE;
	}
	lck_spin_unlock(&region->lock);

	if (__atomic_load_n(&qslot->snd_waiters, __ATOMIC_ACQUIRE) != 0) {
		sq_wake(region, &qslot->deq);
	}

	msize = ipc_kmsg_copyout_size(kmsg, thread->map);
	too_large = msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size;

	thread->ith_kmsg = kmsg;
	thread->ith_seqno = seqno;
	thread->ith_msize = msize;
	thread->ith_state = too_large ? MACH_RCV_TOO_LARGE : MACH_MSG_SUCCESS;
	current_task()->messages_received++;
	return SQ_R_HANDLED;
}

// the receive was a wait the task does itself (mach_msg_sq_receive) and there is nothing to receive
static void sq_receive_wait_locally(dtape_thread_t* dthread, thread_t thread)
{
	dthread->sq_local_wait_result = true;
	thread->ith_kmsg = IKM_NULL;
	thread->ith_seqno = 0;
	thread->ith_state = MACH_RCV_TIMED_OUT;
}

// ipc_mqueue_receive() on a set of the mode: the member that has been ready longest gives its first message
static boolean_t sq_set_receive(ipc_mqueue_t mqueue, mach_msg_option_t option, mach_msg_size_t max_size,
    mach_msg_timeout_t rcv_timeout, thread_t thread, dtape_thread_t* dthread, bool local_wait)
{
	ipc_pset_t pset = ips_from_mq(mqueue);
	dtape_sq_slot_t* pslot = sq_pset_slot(pset);
	dtape_sq_region_t* region;

	if (!pslot) {
		return FALSE;
	}
	region = pslot->region;

	if (option & MACH_PEEK_MSG) {
		goto leave;
	}

	for (uint32_t attempt = 0; attempt < SQ_ATTEMPTS; attempt++) {
		dsq_set_pick_t pick;
		dtape_sq_slot_t* member;
		ipc_port_t port;
		bool usable;
		int result, r;

		lck_spin_lock(&region->lock);
		usable = !region->poisoned && !pslot->closing;
		lck_spin_unlock(&region->lock);
		if (!usable) {
			goto leave;
		}

		// from here to the take, a removal of a member has to see this receive (see dsq_set_member_remove())
		dsq_set_enter(&region->view, pslot->index);
		result = dsq_set_select(&region->view, pslot->index, DSQ_EPOCH_ANY, &pick);
		if (result == DSQ_RETRY) {
			dsq_set_exit(&region->view, pslot->index);
			continue;
		}
		if (result == DSQ_EMPTY) {
			dsq_set_exit(&region->view, pslot->index);
			if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0) {
				// XNU's own path finds no member preposted (the members' queues are in the region) and times out
				return FALSE;
			}
			if (local_wait && dthread) {
				sq_receive_wait_locally(dthread, thread);
				return TRUE;
			}
			// a receive that would block in the server: the set leaves the mode and the receive blocks normally
			goto leave;
		}
		if (result != DSQ_OK) {
			dsq_set_exit(&region->view, pslot->index);
			lck_spin_lock(&region->lock);
			if (!(result == DSQ_CLOSED_Q && pslot->closing)) {
				sq_poison(region, result == DSQ_CLOSED_Q ? "a queue was closed by the task" : "inconsistent queue");
			}
			lck_spin_unlock(&region->lock);
			goto leave;
		}

		member = &region->slots[pick.member];
		lck_spin_lock(&region->lock);
		port = member->port;
		usable = port != IP_NULL && !member->closing && member->set == pslot;
		if (usable) {
			ip_reference(port);
		}
		lck_spin_unlock(&region->lock);
		if (!usable) {
			dsq_set_exit(&region->view, pslot->index);
			continue;
		}

		ip_lock(port);
		imq_lock(&port->ip_messages);
		r = SQ_R_RETRY;
		if (sq_port_slot(port) == member && ip_active(port) && !member->closing) {
			r = sq_receive_node(member, port, &pick, pslot->index, pick.deq, pick.index, option, max_size, thread);
		}
		imq_unlock(&port->ip_messages);
		ip_unlock(port);
		ip_release(port);
		dsq_set_exit(&region->view, pslot->index);

		if (r == SQ_R_HANDLED) {
			return TRUE;
		}
		if (r == SQ_R_LEAVE) {
			goto leave;
		}
	}

leave:
	dtape_sq_pset_leave(pset);
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
		return sq_set_receive(mqueue, option, max_size, rcv_timeout, thread, dthread, local_wait);
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
		int result = dsq_head(&region->view, slot->index, DSQ_EPOCH_ANY, &d, &index);

		if (result == DSQ_RETRY) {
			continue;
		}
		if (result == DSQ_EMPTY) {
			if ((option & MACH_RCV_TIMEOUT) && rcv_timeout == 0) {
				// XNU's own path finds the (empty) port queue and times out
				goto out;
			}
			if (local_wait && dthread) {
				// the task waits for the queue itself (see the mach_msg_sq_receive call)
				sq_receive_wait_locally(dthread, thread);
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

		int r = sq_receive_node(slot, port, NULL, DSQ_NONE, d, index, option, max_size, thread);
		if (r == SQ_R_RETRY) {
			continue;
		}
		if (r == SQ_R_HANDLED) {
			handled = TRUE;
			goto out;
		}
		goto leave;
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
	dtape_sq_region_t* region;
	uint64_t h, d;
	uint32_t len, tokens, made_queued;
	bool closing;
	int result = DSQ_CLOSED_Q;

	if (!slot) {
		return;
	}
	region = slot->region;

	// the port lock keeps the server's own publishes and takes away, so only the task changes the words.
	// the snapshot is the queue at one instant: the counts below are what XNU would report at that instant
	lck_spin_lock(&region->lock);
	closing = slot->closing;
	lck_spin_unlock(&region->lock);
	if (!closing) {
		result = dsq_snapshot(&region->view, slot->index, SQ_ATTEMPTS, &h, &d, &made_queued);
	}

	if (result != DSQ_OK) {
		// closed already, or the task kept dequeuing (or broke its queue): the port's own queue then
		// has everything, and the counts are XNU's own
		dtape_sq_port_leave(port, DSQ_CLOSE_OTHER);
		imq_lock(&port->ip_messages);
		status->mps_seqno = port->ip_messages.imq_seqno;
		status->mps_msgcount = port->ip_messages.imq_msgcount;
		imq_unlock(&port->ip_messages);
		status->mps_mscount = port->ip_mscount;
		status->mps_srights = port->ip_srights > 0;
		return;
	}

	tokens = slot->tokens_published - slot->tokens_taken;
	len = DSQ_LEN(h, d);

	status->mps_msgcount += len;
	status->mps_seqno = dsq_seqno(&region->view, slot->index, d);
	// every MAKE_SEND message published so far: the dequeued ones and the queued ones
	status->mps_mscount += DSQ_D_MADE(d) + made_queued;
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
