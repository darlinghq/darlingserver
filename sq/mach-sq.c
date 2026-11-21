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

// The operations on shared message queues (see mach-sq.h). Built into darlingserver's duct-tape
// and into libsystem_kernel, so it uses nothing but compiler builtins.
//
// Every operation is lock-free: no thread of the task can hold anything the server would wait for,
// and the server's own loops are bounded.

#include <darlingserver/mach-sq.h>

_Static_assert(sizeof(dsq_node_t) == DSQ_NODE_SIZE, "node size");
_Static_assert(offsetof(dsq_node_t, msg) == DSQ_NODE_HEADER, "node header size");
_Static_assert(sizeof(dsq_s_header_t) == 1024, "S header size");
_Static_assert(sizeof(dsq_name_entry_t) == 12, "name entry size");
_Static_assert(sizeof(dsq_s_slot_t) == 32, "S slot size");
_Static_assert(sizeof(dsq_q_slot_t) == 64, "Q slot size");
_Static_assert(offsetof(dsq_q_slot_t, deq) == 8, "Q slot layout");
_Static_assert(DSQ_NODES < DSQ_NONE, "node indices fit in 16 bits");
_Static_assert(DSQ_SLOTS <= 0x10000, "slot numbers fit in 16 bits");

#define DSQ_NAME_MASK (DSQ_NAMES - 1)
#define DSQ_SEQLOCK_TRIES 1000

static inline void dsq_pause(void)
{
#if defined(__i386__) || defined(__x86_64__)
	__builtin_ia32_pause();
#elif defined(__aarch64__)
	__asm__ __volatile__("yield");
#endif
}

static inline uint64_t dsq_tagged(uint32_t index, uint64_t previous)
{
	return (uint64_t) (index & 0xffffu) | (((previous >> 32) + 1) << 32);
}

// the first 8 bytes of a node: seq | slot << 32 | next << 48
static inline uint64_t dsq_node_key(const dsq_node_t* n)
{
	return __atomic_load_n((const dsq_word_t*) n, __ATOMIC_ACQUIRE);
}

int dsq_publish(const dsq_view_t* v, uint32_t slot, uint32_t index, uint32_t epoch, uint32_t qlimit,
		uint32_t attempts, uint32_t* seq_out)
{
	dsq_node_t* n = dsq_node(v, index);
	if (n == NULL || slot >= DSQ_SLOTS)
		return DSQ_CORRUPT;

	dsq_q_slot_t* qs = &v->q->slots[slot];

	for (uint32_t i = 0; attempts == 0 || i < attempts; i++)
	{
		// deq before head: deq only grows, so a length computed from an older deq is never too small,
		// and an open head means deq was read before the slot closed
		uint64_t d = (qlimit != UINT32_MAX) ? dsq_load(&qs->deq) : 0;
		uint64_t h = dsq_load(&qs->head);
		if (DSQ_IS_CLOSED(h))
			return DSQ_CLOSED_Q;
		if (epoch != DSQ_EPOCH_ANY && DSQ_H_EPOCH(h) != epoch)
			return DSQ_STALE;
		if (qlimit != UINT32_MAX && DSQ_LEN(h, d) >= qlimit)
			return DSQ_FULL;

		uint32_t seq = DSQ_H_SEQ(h);
		uint64_t key = (uint64_t) seq | ((uint64_t) slot << 32) | ((uint64_t) DSQ_H_TOP(h) << 48);
		__atomic_store_n((dsq_word_t*) n, key, __ATOMIC_RELAXED);

		uint64_t nh = DSQ_H_MAKE(seq + 1, false, index, DSQ_H_EPOCH(h));
		if (__atomic_compare_exchange_n(&qs->head, &h, nh, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
		{
			__atomic_store_n(&qs->hint[seq % DSQ_HINTS], (uint16_t) index, __ATOMIC_RELAXED);
			if (seq_out != NULL)
				*seq_out = seq;
			return DSQ_OK;
		}
	}
	return DSQ_CONTENDED;
}

int dsq_head(const dsq_view_t* v, uint32_t slot, uint64_t* deq_out, uint32_t* index_out)
{
	if (slot >= DSQ_SLOTS)
		return DSQ_CORRUPT;

	dsq_q_slot_t* qs = &v->q->slots[slot];
	// deq before head (see mach-sq.h): an open head means `d` is still the queue's
	uint64_t d = dsq_load(&qs->deq);
	uint64_t h = dsq_load(&qs->head);

	if (DSQ_IS_CLOSED(h))
		return DSQ_CLOSED_Q;

	uint32_t want = DSQ_D_DEQ(d);
	uint32_t len = DSQ_LEN(h, d);
	if (len == 0)
		return DSQ_EMPTY;
	if (len > DSQ_NODES)
		return DSQ_RETRY;

	// a node is the one at `want` only if both its seq and its slot match; seq never repeats on a slot
	uint64_t match = (uint64_t) want | ((uint64_t) slot << 32);
	uint32_t index = __atomic_load_n(&qs->hint[want % DSQ_HINTS], __ATOMIC_RELAXED);
	const dsq_node_t* n = dsq_node(v, index);

	if (n == NULL || (dsq_node_key(n) & 0xffffffffffffull) != match)
	{
		index = DSQ_H_TOP(h);
		for (uint32_t i = 0; ; i++)
		{
			if (i == len)
				return DSQ_RETRY;
			n = dsq_node(v, index);
			if (n == NULL)
				return DSQ_RETRY;
			uint64_t key = dsq_node_key(n);
			if ((key & 0xffffffffffffull) == match)
				break;
			index = (uint32_t) (key >> 48);
		}
	}

	*deq_out = d;
	*index_out = index;
	return DSQ_OK;
}

uint32_t dsq_seqno(const dsq_view_t* v, uint32_t slot, uint64_t deq)
{
	return DSQ_D_COUNT(deq) + __atomic_load_n(&v->s->slots[slot].seqno_base, __ATOMIC_ACQUIRE);
}

bool dsq_take(const dsq_view_t* v, uint32_t slot, uint64_t deq, bool made_send, uint32_t* seqno_out)
{
	dsq_q_slot_t* qs = &v->q->slots[slot];
	// read before the CAS: the slot's base is the one of this deq word only while the CAS can succeed
	uint32_t seqno = dsq_seqno(v, slot, deq);
	uint64_t next = DSQ_D_MAKE(DSQ_D_COUNT(deq) + 1, DSQ_D_MADE(deq) + (made_send ? 1 : 0));

	if (!__atomic_compare_exchange_n(&qs->deq, &deq, next, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
		return false;
	*seqno_out = seqno;
	return true;
}

void dsq_close(const dsq_view_t* v, uint32_t slot, uint64_t* head_out, uint64_t* deq_out)
{
	dsq_q_slot_t* qs = &v->q->slots[slot];
	// head first: no publish succeeds afterwards, and a take reads head after deq. then any change of the
	// deq word makes a take that read it before fail; the value it had is the queue's final state
	uint64_t h = __atomic_fetch_or(&qs->head, (uint64_t) DSQ_CLOSED, __ATOMIC_SEQ_CST);
	uint64_t d = __atomic_fetch_add(&qs->deq, 1, __ATOMIC_SEQ_CST);
	*head_out = h | DSQ_CLOSED;
	*deq_out = d;
}

int dsq_snapshot(const dsq_view_t* v, uint32_t slot, uint32_t attempts, uint64_t* head_out,
		uint64_t* deq_out, uint32_t* made_queued_out)
{
	if (slot >= DSQ_SLOTS)
		return DSQ_CORRUPT;

	dsq_q_slot_t* qs = &v->q->slots[slot];

	for (uint32_t i = 0; i < attempts; i++)
	{
		uint64_t d = dsq_load(&qs->deq);
		uint64_t h = dsq_load(&qs->head);
		uint32_t len = DSQ_LEN(h, d);
		uint32_t index = DSQ_H_TOP(h);
		uint32_t made = 0;
		bool walked = true;

		if (DSQ_IS_CLOSED(h))
			return DSQ_CLOSED_Q;

		if (len > DSQ_NODES)
			walked = false;
		// newest to oldest: seq - 1, ..., deq
		for (uint32_t k = 0; walked && k < len; k++)
		{
			const dsq_node_t* n = dsq_node(v, index);
			if (n == NULL)
			{
				walked = false;
				break;
			}
			uint64_t key = dsq_node_key(n);
			uint32_t want = (DSQ_H_SEQ(h) - 1 - k) & DSQ_SEQ_MASK;
			if ((uint32_t) key != want || (uint16_t) (key >> 32) != slot)
			{
				walked = false;
				break;
			}
			uint32_t flags = __atomic_load_n(&n->flags, __ATOMIC_RELAXED);
			if (index < DSQ_TNODES && (flags & DSQ_NODE_INLINE) && (flags & DSQ_NODE_MADE_SEND))
				made++;
			index = (uint32_t) (key >> 48);
		}

		// the node reads come before the second deq read
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (dsq_load(&qs->deq) != d)
			continue;
		// deq stayed `d` from before head was read until after the walk, so the walk was of queued nodes
		if (!walked)
			return DSQ_CORRUPT;

		*head_out = h;
		*deq_out = d;
		*made_queued_out = made;
		return DSQ_OK;
	}
	return DSQ_CONTENDED;
}

uint32_t dsq_collect(const dsq_view_t* v, uint32_t slot, uint64_t head, uint64_t deq, uint16_t* out)
{
	uint32_t len = DSQ_LEN(head, deq);
	uint32_t base = DSQ_D_DEQ(deq);
	uint32_t index = DSQ_H_TOP(head);
	uint32_t found = 0;

	if (len > DSQ_NODES)
		return 0;

	// newest to oldest: seq - 1, seq - 2, ..., deq
	for (uint32_t i = 0; i < len; i++)
	{
		const dsq_node_t* n = dsq_node(v, index);
		if (n == NULL)
			break;
		uint64_t key = dsq_node_key(n);
		uint32_t want = (DSQ_H_SEQ(head) - 1 - i) & DSQ_SEQ_MASK;
		if ((uint32_t) key != want || (uint16_t) (key >> 32) != slot)
			break;
		out[(want - base) & DSQ_SEQ_MASK] = (uint16_t) index;
		found++;
		index = (uint32_t) (key >> 48);
	}
	return found;
}

static void dsq_push_chain(dsq_word_t* top, uint16_t* next, uint32_t first, uint32_t last)
{
	uint64_t t = __atomic_load_n(top, __ATOMIC_ACQUIRE);
	for (;;)
	{
		__atomic_store_n(&next[last], (uint16_t) t, __ATOMIC_RELAXED);
		if (__atomic_compare_exchange_n(top, &t, dsq_tagged(first, t), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			return;
	}
}

uint32_t dsq_task_node_alloc(const dsq_view_t* v)
{
	dsq_q_region_t* q = v->q;

	for (;;)
	{
		uint64_t t = __atomic_load_n(&q->free_top, __ATOMIC_ACQUIRE);
		uint32_t index = (uint32_t) (t & 0xffffu);

		if (index == DSQ_NONE)
		{
			// take over the nodes the server gave back, all at once
			uint64_t r = __atomic_load_n(&q->returned_top, __ATOMIC_ACQUIRE);
			uint32_t first = (uint32_t) (r & 0xffffu);
			if (first >= DSQ_TNODES)
				return DSQ_NONE;
			if (!__atomic_compare_exchange_n(&q->returned_top, &r, dsq_tagged(DSQ_NONE, r), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
				continue;

			uint32_t rest = __atomic_load_n(&q->free_next[first], __ATOMIC_RELAXED);
			if (rest < DSQ_TNODES)
			{
				uint32_t last = rest;
				for (uint32_t i = 0; i < DSQ_TNODES; i++)
				{
					uint32_t nx = __atomic_load_n(&q->free_next[last], __ATOMIC_RELAXED);
					if (nx >= DSQ_TNODES)
						break;
					last = nx;
				}
				dsq_push_chain(&q->free_top, q->free_next, rest, last);
			}
			return first;
		}
		if (index >= DSQ_TNODES)
			return DSQ_NONE;

		uint32_t next = __atomic_load_n(&q->free_next[index], __ATOMIC_RELAXED);
		if (__atomic_compare_exchange_n(&q->free_top, &t, dsq_tagged(next, t), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			return index;
	}
}

void dsq_task_node_free(const dsq_view_t* v, uint32_t index)
{
	if (index < DSQ_TNODES)
		dsq_push_chain(&v->q->free_top, v->q->free_next, index, index);
}

bool dsq_server_node_return(const dsq_view_t* v, uint32_t index, uint32_t attempts)
{
	dsq_q_region_t* q = v->q;
	uint64_t t = __atomic_load_n(&q->returned_top, __ATOMIC_ACQUIRE);

	if (index >= DSQ_TNODES)
		return false;

	for (uint32_t i = 0; i < attempts; i++)
	{
		__atomic_store_n(&q->free_next[index], (uint16_t) t, __ATOMIC_RELAXED);
		if (__atomic_compare_exchange_n(&q->returned_top, &t, dsq_tagged(index, t), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			return true;
	}
	return false;
}

void dsq_region_init(const dsq_view_t* v)
{
	dsq_s_region_t* s = v->s;
	dsq_q_region_t* q = v->q;

	s->hdr.magic = DSQ_MAGIC;
	s->hdr.version = DSQ_VERSION;
	s->hdr.s_size = (uint32_t) DSQ_S_SIZE;
	s->hdr.q_size = (uint32_t) DSQ_Q_SIZE;

	for (uint32_t i = 0; i < DSQ_SLOTS; i++)
	{
		q->slots[i].head = DSQ_H_MAKE(0, true, DSQ_NONE, 0);
		q->slots[i].deq = DSQ_D_MAKE(0, 0);
		for (uint32_t k = 0; k < DSQ_HINTS; k++)
			q->slots[i].hint[k] = DSQ_NONE;
	}

	for (uint32_t i = 0; i < DSQ_TNODES; i++)
		q->free_next[i] = (uint16_t) (i + 1 < DSQ_TNODES ? i + 1 : DSQ_NONE);
	q->free_top = 0;
	q->returned_top = DSQ_NONE;

	__atomic_thread_fence(__ATOMIC_RELEASE);
}

uint32_t dsq_slot_open(const dsq_view_t* v, uint32_t slot, uint32_t seqno)
{
	dsq_q_slot_t* qs = &v->q->slots[slot];
	uint64_t h = dsq_load(&qs->head);
	uint32_t epoch = (DSQ_H_EPOCH(h) + 1) & 0xffffu;

	for (uint32_t k = 0; k < DSQ_HINTS; k++)
		__atomic_store_n(&qs->hint[k], (uint16_t) DSQ_NONE, __ATOMIC_RELAXED);

	// seq and deq continue (deq to the next count that matches seq), so no old head or deq value comes
	// back; the queue is empty (deq == seq), no MAKE_SEND message has been dequeued yet, and
	// deq + seqno_base is the port's seqno. head opens last: until then nothing can be published or taken
	uint32_t count = DSQ_D_COUNT(dsq_load(&qs->deq));
	count += (DSQ_H_SEQ(h) - count) & DSQ_SEQ_MASK;
	__atomic_store_n(&v->s->slots[slot].seqno_base, seqno - count, __ATOMIC_RELEASE);
	__atomic_store_n(&qs->deq, DSQ_D_MAKE(count, 0), __ATOMIC_RELEASE);
	__atomic_store_n(&qs->head, DSQ_H_MAKE(DSQ_H_SEQ(h), false, DSQ_NONE, epoch), __ATOMIC_RELEASE);
	return epoch;
}

bool dsq_slot_bump_epoch(const dsq_view_t* v, uint32_t slot, uint32_t attempts, uint32_t* epoch_out)
{
	dsq_q_slot_t* qs = &v->q->slots[slot];
	uint64_t h = dsq_load(&qs->head);

	for (uint32_t i = 0; i < attempts; i++)
	{
		if (DSQ_IS_CLOSED(h))
			return false;
		uint32_t epoch = (DSQ_H_EPOCH(h) + 1) & 0xffffu;
		uint64_t nh = (h & 0x0000ffffffffffffull) | ((uint64_t) epoch << 48);
		if (__atomic_compare_exchange_n(&qs->head, &h, nh, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		{
			*epoch_out = epoch;
			return true;
		}
	}
	return false;
}

static inline uint32_t dsq_name_hash(uint32_t name)
{
	return (name * 0x9E3779B1u) >> (32 - 10);
}
_Static_assert(DSQ_NAMES == 1 << 10, "dsq_name_hash() makes 10-bit hashes");

bool dsq_name_lookup(const dsq_view_t* v, uint32_t name, dsq_name_entry_t* out)
{
	const dsq_s_region_t* s = v->s;

	if (name == 0)
		return false;

	for (uint32_t tries = 0; tries < DSQ_SEQLOCK_TRIES; tries++)
	{
		uint32_t s1 = __atomic_load_n(&s->hdr.names_seq, __ATOMIC_ACQUIRE);
		if (s1 & 1)
		{
			dsq_pause();
			continue;
		}

		bool found = false;
		uint32_t i = dsq_name_hash(name);
		for (uint32_t k = 0; k < DSQ_NAMES; k++, i = (i + 1) & DSQ_NAME_MASK)
		{
			const uint32_t* w = (const uint32_t*) &s->names[i];
			uint32_t entry_name = __atomic_load_n(&w[0], __ATOMIC_RELAXED);
			if (entry_name == 0)
				break;
			if (entry_name == name)
			{
				uint32_t w1 = __atomic_load_n(&w[1], __ATOMIC_RELAXED);
				out->name = name;
				out->slot = (uint16_t) w1;
				out->rights = (uint8_t) (w1 >> 16);
				out->pad = 0;
				out->epoch = __atomic_load_n(&w[2], __ATOMIC_RELAXED);
				found = true;
				break;
			}
		}

		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (__atomic_load_n(&s->hdr.names_seq, __ATOMIC_RELAXED) == s1)
			return found && out->slot < DSQ_SLOTS;
	}
	return false;
}

static inline void dsq_names_write_begin(dsq_s_region_t* s)
{
	__atomic_store_n(&s->hdr.names_seq, s->hdr.names_seq + 1, __ATOMIC_RELAXED);
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

static inline void dsq_names_write_end(dsq_s_region_t* s)
{
	__atomic_store_n(&s->hdr.names_seq, s->hdr.names_seq + 1, __ATOMIC_RELEASE);
}

static inline void dsq_name_store(dsq_name_entry_t* e, uint32_t name, uint32_t slot, uint32_t rights, uint32_t epoch)
{
	uint32_t* w = (uint32_t*) e;
	__atomic_store_n(&w[1], (slot & 0xffffu) | ((rights & 0xffu) << 16), __ATOMIC_RELAXED);
	__atomic_store_n(&w[2], epoch, __ATOMIC_RELAXED);
	__atomic_store_n(&w[0], name, __ATOMIC_RELAXED);
}

bool dsq_name_set(const dsq_view_t* v, uint32_t name, uint32_t slot, uint32_t rights, uint32_t epoch)
{
	dsq_s_region_t* s = v->s;
	uint32_t i = dsq_name_hash(name);

	for (uint32_t k = 0; k < DSQ_NAMES; k++, i = (i + 1) & DSQ_NAME_MASK)
	{
		dsq_name_entry_t* e = &s->names[i];
		if (e->name == name || e->name == 0)
		{
			dsq_names_write_begin(s);
			dsq_name_store(e, name, slot, rights, epoch);
			dsq_names_write_end(s);
			return true;
		}
	}
	return false;
}

void dsq_name_remove(const dsq_view_t* v, uint32_t name)
{
	dsq_s_region_t* s = v->s;
	uint32_t i = dsq_name_hash(name);
	uint32_t k;

	for (k = 0; k < DSQ_NAMES; k++, i = (i + 1) & DSQ_NAME_MASK)
	{
		if (s->names[i].name == 0)
			return;
		if (s->names[i].name == name)
			break;
	}
	if (k == DSQ_NAMES)
		return;

	dsq_names_write_begin(s);

	// linear-probing deletion: move later entries of the probe chain into the hole
	for (uint32_t j = i, n = 0; n < DSQ_NAMES; n++)
	{
		j = (j + 1) & DSQ_NAME_MASK;
		dsq_name_entry_t* e = &s->names[j];
		if (e->name == 0)
			break;
		uint32_t home = dsq_name_hash(e->name);
		// can the entry at j stay where it is (its home is cyclically within (i, j])?
		bool stays = (i <= j) ? (i < home && home <= j) : (i < home || home <= j);
		if (stays)
			continue;
		dsq_name_store(&s->names[i], e->name, e->slot, e->rights, e->epoch);
		i = j;
	}
	dsq_name_store(&s->names[i], 0, 0, 0, 0);

	dsq_names_write_end(s);
}

void dsq_tokens_push(const dsq_view_t* v, const uint32_t sec_token[2], const uint32_t audit_token[8])
{
	dsq_s_header_t* hdr = &v->s->hdr;
	uint32_t gen = hdr->token_gen + 1;
	dsq_token_entry_t* e = &hdr->tokens[gen % DSQ_TOKEN_HISTORY];

	__atomic_store_n(&hdr->token_seq, hdr->token_seq + 1, __ATOMIC_RELAXED);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	e->gen = gen;
	for (int i = 0; i < 2; i++)
		e->sec_token[i] = sec_token[i];
	for (int i = 0; i < 8; i++)
		e->audit_token[i] = audit_token[i];
	__atomic_store_n(&hdr->token_gen, gen, __ATOMIC_RELAXED);
	__atomic_store_n(&hdr->token_seq, hdr->token_seq + 1, __ATOMIC_RELEASE);
}

uint32_t dsq_tokens_current(const dsq_view_t* v)
{
	return __atomic_load_n(&v->s->hdr.token_gen, __ATOMIC_ACQUIRE);
}

void dsq_tokens_lookup(const dsq_view_t* v, uint32_t gen, uint32_t sec_token[2], uint32_t audit_token[8])
{
	const dsq_s_header_t* hdr = &v->s->hdr;

	for (uint32_t tries = 0; tries < DSQ_SEQLOCK_TRIES; tries++)
	{
		uint32_t s1 = __atomic_load_n(&hdr->token_seq, __ATOMIC_ACQUIRE);
		if (s1 & 1)
		{
			dsq_pause();
			continue;
		}

		const dsq_token_entry_t* e = &hdr->tokens[gen % DSQ_TOKEN_HISTORY];
		if (__atomic_load_n(&e->gen, __ATOMIC_RELAXED) != gen)
			e = &hdr->tokens[__atomic_load_n(&hdr->token_gen, __ATOMIC_RELAXED) % DSQ_TOKEN_HISTORY];
		for (int i = 0; i < 2; i++)
			sec_token[i] = __atomic_load_n(&e->sec_token[i], __ATOMIC_RELAXED);
		for (int i = 0; i < 8; i++)
			audit_token[i] = __atomic_load_n(&e->audit_token[i], __ATOMIC_RELAXED);

		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (__atomic_load_n(&hdr->token_seq, __ATOMIC_RELAXED) == s1)
			return;
	}
}

uint32_t dsq_trailer_size(uint32_t option)
{
	// MACH_RCV_TRAILER_ELEMENTS: NULL, SEQNO, SENDER, AUDIT, CTX, (5, 6), AV; anything else: the largest
	static const uint8_t sizes[16] = { 8, 12, 20, 52, 60, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68 };
	return sizes[(option >> 24) & 0xf];
}

static inline void dsq_put32(uint8_t* p, uint32_t value)
{
	__builtin_memcpy(p, &value, sizeof(value));
}

uint32_t dsq_build_received(const dsq_node_t* node, uint32_t rcv_name, uint32_t option, uint32_t seqno,
		uint64_t context, const uint32_t sec_token[2], const uint32_t audit_token[8], uint8_t* out)
{
	uint32_t size = node->size;
	uint32_t id;
	uint8_t trailer[DSQ_TRAILER_MAX];
	uint32_t trailer_size;

	__builtin_memcpy(&id, &node->msg[20], sizeof(id));

	// the header as the server's copyout leaves it: the destination's PORT_SEND right is consumed into
	// the local field (the receive right's name), no reply port, no voucher
	dsq_put32(out + 0, 0x1100); // MACH_MSGH_BITS_SET(0, MACH_MSG_TYPE_PORT_SEND, 0, 0)
	dsq_put32(out + 4, size);
	dsq_put32(out + 8, 0);
	dsq_put32(out + 12, rcv_name);
	dsq_put32(out + 16, 0);
	dsq_put32(out + 20, id);
	__builtin_memcpy(out + DSQ_MSG_MIN, &node->msg[DSQ_MSG_MIN], size - DSQ_MSG_MIN);

	// the format-0 trailer: type, size, seqno, sender (security token), audit token, context, ad, labels.
	// without a trailer request only the minimal one (type and size) is copied out, and nothing else is set
	__builtin_memset(trailer, 0, sizeof(trailer));
	if ((option & 0x0f000000u) == 0)
	{
		trailer_size = 8;
		dsq_put32(trailer + 4, trailer_size);
	}
	else
	{
		trailer_size = dsq_trailer_size(option);
		dsq_put32(trailer + 4, trailer_size);
		dsq_put32(trailer + 8, seqno);
		dsq_put32(trailer + 12, sec_token[0]);
		dsq_put32(trailer + 16, sec_token[1]);
		for (int i = 0; i < 8; i++)
			dsq_put32(trailer + 20 + 4 * i, audit_token[i]);
		__builtin_memcpy(trailer + 52, &context, sizeof(context));
	}
	__builtin_memcpy(out + size, trailer, trailer_size);

	return size + trailer_size;
}
