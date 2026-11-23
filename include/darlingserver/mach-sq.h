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

#ifndef _DARLINGSERVER_MACH_SQ_H_
#define _DARLINGSERVER_MACH_SQ_H_

// Shared message queues ("shared-queue mode") of Mach ports.
//
// darlingserver owns every port, right and name. For a port whose receive right is in a task T
// that has attached a shared region, the server may keep the port's message queue in memory that
// it shares with T, instead of in the port's ipc_mqueue. Threads of T then send simple messages
// to the port, and receive from it, without a call to darlingserver; everything else (messages
// from other tasks, complex messages, notifications) is still sent by the server, which links a
// "token" node for each such message into the same queue, so the queue has a single order.
// The server takes a port out of the mode (and moves the queue into the ipc_mqueue) with two
// atomic fetch-or operations and never waits for T to do so.
//
// This file and mach-sq.c are the one implementation of the queue format and its operations;
// darlingserver (duct-tape) and libsystem_kernel both build them. Nothing here depends on the
// pointer size: the format is the same for 32-bit and 64-bit tasks.
//
// Two shared memory objects make up a region:
//   S: written only by the server (T maps it read-only; it is sealed against writable mappings):
//      header (token history), name table, per-slot settings, the server's node pool.
//   Q: written by both: per-slot queue words, T's node pool and its free stacks.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DSQ_MAGIC        0x31515344u // "DSQ1"
#define DSQ_VERSION      2

#define DSQ_SLOTS        512
#define DSQ_TNODES       1024        // nodes of the task (in Q), indices [0, DSQ_TNODES)
#define DSQ_SNODES       256         // nodes of the server (in S), indices [DSQ_TNODES, DSQ_NODES)
#define DSQ_NODES        (DSQ_TNODES + DSQ_SNODES)
#define DSQ_NAMES        1024        // name table entries (a power of two)
#define DSQ_TOKEN_HISTORY 8          // audit token history entries (a power of two)
#define DSQ_HINTS        8           // hint ring entries per slot (a power of two)
#define DSQ_NONE         0xffffu     // "no node"

#define DSQ_NODE_SIZE    256
#define DSQ_NODE_HEADER  16
#define DSQ_MSG_MAX      (DSQ_NODE_SIZE - DSQ_NODE_HEADER) // largest message a node holds (240)
#define DSQ_MSG_MIN      24          // a user-space message header

// the largest trailer a receive can ask for (mach_msg_max_trailer_t as darlingserver copies it out)
#define DSQ_TRAILER_MAX  68

// node flags
#define DSQ_NODE_INLINE    0x1 // the message itself is in the node
#define DSQ_NODE_TOKEN     0x2 // the message is a kmsg the server holds (aux = token id)
#define DSQ_NODE_MADE_SEND 0x4 // the destination was MAKE_SEND (counted in the deq word when it is dequeued)

// rights a name table entry records
#define DSQ_RIGHT_SEND    0x1
#define DSQ_RIGHT_RECEIVE 0x2

// close reasons (S slot `close_reason`)
#define DSQ_CLOSE_NONE      0
#define DSQ_CLOSE_MOVED     1 // the receive right left the task
#define DSQ_CLOSE_DESTROYED 2 // the port was destroyed
#define DSQ_CLOSE_OTHER     3 // any other reason (set membership, a knote, a notification request, ...)

// S header flags
#define DSQ_FLAG_POISONED 0x1 // the server found an inconsistency; nothing may use the region any more

// head word:
//   bits 0..30 seq (nodes ever published, mod 2^31), bit 31 closed, bits 32..47 top node, bits 48..63 epoch
// deq word:
//   bits 0..31 deq (nodes ever dequeued, mod 2^32; its low 31 bits count in step with seq),
//   bits 32..63 made (MAKE_SEND nodes ever dequeued, mod 2^32)
// The port's next seqno is deq + the slot's seqno_base (S). The deq word has no closed bit: only the head
// closes. The server closes a slot by closing the head and then changing the deq word, so a take that
// read the old deq word fails; whoever reads the deq word reads the head after it, and a closed head
// means the deq word read before it is no longer the queue's.
// The make-send count of a port in the mode is ip_mscount + made + the MAKE_SEND nodes still queued
// (dsq_snapshot()); every word is 64 bits, also on i386.
#define DSQ_SEQ_MASK     0x7fffffffu
#define DSQ_CLOSED       0x80000000u
#define DSQ_H_SEQ(h)     ((uint32_t)(h) & DSQ_SEQ_MASK)
#define DSQ_H_TOP(h)     ((uint32_t)((h) >> 32) & 0xffffu)
#define DSQ_H_EPOCH(h)   ((uint32_t)((h) >> 48) & 0xffffu)
#define DSQ_H_MAKE(seq, closed, top, epoch) \
	(((uint64_t)((seq) & DSQ_SEQ_MASK)) | ((closed) ? (uint64_t)DSQ_CLOSED : 0) | \
	 ((uint64_t)((top) & 0xffffu) << 32) | ((uint64_t)((epoch) & 0xffffu) << 48))
#define DSQ_D_DEQ(d)     ((uint32_t)(d) & DSQ_SEQ_MASK)   // compared with the head's seq
#define DSQ_D_COUNT(d)   ((uint32_t)(d))                  // all 32 bits (for the seqno)
#define DSQ_D_MADE(d)    ((uint32_t)((d) >> 32))
#define DSQ_D_MAKE(count, made) ((uint64_t)(uint32_t)(count) | ((uint64_t)(uint32_t)(made) << 32))
#define DSQ_IS_CLOSED(h) (((uint32_t)(h) & DSQ_CLOSED) != 0) // head words only
#define DSQ_LEN(h, d)    ((DSQ_H_SEQ(h) - DSQ_D_DEQ(d)) & DSQ_SEQ_MASK)

// "any epoch" for server publishes
#define DSQ_EPOCH_ANY    0x10000u

// returned by the mach_msg_sq_receive call (never a mach_msg_return_t): the port's shared queue is
// empty and the receive would wait, so the task waits for the queue itself
#define DSQ_RCV_WAIT_LOCALLY 0x7fff5351

#define DSQ_ALIGN(n) __attribute__((aligned(n)))

// every queue word is 8-byte aligned, also on i386 (where uint64_t alone is only 4-byte aligned), so its
// loads are single instructions there too
typedef uint64_t dsq_word_t __attribute__((aligned(8)));

typedef struct dsq_node {
	// written as one 64-bit word before the node is published: a reader loads it at once,
	// so a (seq, slot) pair it sees always belongs to one publish
	uint32_t seq;   // the slot's head seq this node was published at
	uint16_t slot;  // the slot it was published on
	uint16_t next;  // the next older node of the queue (DSQ_NONE: none)
	uint16_t flags; // DSQ_NODE_*
	uint16_t size;  // INLINE: the message size; TOKEN: the kmsg's user-visible size (at most 0xffff)
	uint32_t aux;   // INLINE: token history generation at send (for the task's own receives; the server keeps its own record); TOKEN: token id
	uint8_t msg[DSQ_MSG_MAX];
} DSQ_ALIGN(8) dsq_node_t;

typedef struct dsq_token_entry {
	uint32_t gen;
	uint32_t sec_token[2];
	uint32_t audit_token[8];
} dsq_token_entry_t;

typedef struct dsq_s_header {
	uint32_t magic;
	uint32_t version;
	uint32_t s_size;
	uint32_t q_size;
	uint32_t flags;      // DSQ_FLAG_*
	uint32_t token_seq;  // seqlock of the token history (odd while the server writes it)
	uint32_t token_gen;  // the current generation
	uint32_t names_seq;  // seqlock of the name table (odd while the server writes it)
	dsq_token_entry_t tokens[DSQ_TOKEN_HISTORY];
	uint8_t pad[1024 - 32 - DSQ_TOKEN_HISTORY * sizeof(dsq_token_entry_t)];
} dsq_s_header_t;

typedef struct dsq_name_entry {
	uint32_t name;    // 0: unused
	uint16_t slot;
	uint8_t rights;   // DSQ_RIGHT_*
	uint8_t pad;
	uint32_t epoch;   // the slot's head epoch these rights belong to
} dsq_name_entry_t;

typedef struct dsq_s_slot {
	uint32_t name;         // the receive right's name
	uint32_t qlimit;
	dsq_word_t context DSQ_ALIGN(8); // the port's context (for the trailer)
	uint32_t close_reason; // DSQ_CLOSE_*, written before the slot closes
	uint32_t gen;          // changes whenever the slot is given to another port
	uint32_t seqno_base;   // the port's next seqno is the deq word's deq + this (mod 2^32)
	uint32_t pad;
} DSQ_ALIGN(8) dsq_s_slot_t;

typedef struct dsq_s_region {
	dsq_s_header_t hdr;
	dsq_name_entry_t names[DSQ_NAMES];
	dsq_s_slot_t slots[DSQ_SLOTS];
	dsq_node_t nodes[DSQ_SNODES];
} DSQ_ALIGN(64) dsq_s_region_t;

typedef struct dsq_q_slot {
	dsq_word_t head;            // see above
	dsq_word_t deq;             // see above
	uint32_t rcv_waiters;       // receivers waiting on the low half of `head`
	uint32_t snd_waiters;       // senders waiting for room on the low half of `deq`
	uint16_t hint[DSQ_HINTS];   // hint[seq % DSQ_HINTS] = the node published at seq (only a hint)
	uint8_t pad[24];
} DSQ_ALIGN(64) dsq_q_slot_t;

typedef struct dsq_q_region {
	dsq_q_slot_t slots[DSQ_SLOTS];
	// Treiber stacks of the task's free nodes: index (DSQ_NONE: empty) | ABA tag << 32
	dsq_word_t free_top DSQ_ALIGN(64);
	// nodes the server has taken from the task's queues and gives back (pushed by the server only)
	dsq_word_t returned_top DSQ_ALIGN(64);
	uint16_t free_next[DSQ_TNODES] DSQ_ALIGN(64);
	dsq_node_t nodes[DSQ_TNODES] DSQ_ALIGN(64);
} DSQ_ALIGN(64) dsq_q_region_t;

#define DSQ_PAGE_ROUND(x) (((x) + 4095) & ~(size_t)4095)
#define DSQ_S_SIZE DSQ_PAGE_ROUND(sizeof(dsq_s_region_t))
#define DSQ_Q_SIZE DSQ_PAGE_ROUND(sizeof(dsq_q_region_t))

typedef struct dsq_view {
	dsq_s_region_t* s;
	dsq_q_region_t* q;
} dsq_view_t;

// results of the operations below
enum {
	DSQ_OK = 0,
	DSQ_EMPTY,      // nothing queued
	DSQ_CLOSED_Q,   // the slot is closed
	DSQ_STALE,      // the epoch changed (a right changed): look the name up again
	DSQ_FULL,       // the queue holds qlimit messages
	DSQ_CONTENDED,  // the bounded number of attempts was used up
	DSQ_RETRY,      // the queue changed under a reader: try again
	DSQ_CORRUPT,    // the queue's contents are inconsistent
	DSQ_UNSUPPORTED,
};

static inline dsq_node_t* dsq_node(const dsq_view_t* v, uint32_t index)
{
	if (index < DSQ_TNODES)
		return &v->q->nodes[index];
	if (index < DSQ_NODES)
		return &v->s->nodes[index - DSQ_TNODES];
	return NULL;
}

static inline uint64_t dsq_load(const volatile dsq_word_t* p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

// --- queue operations -------------------------------------------------------------------------

// Links node `index` (filled in completely by the caller) into `slot`'s queue.
// `epoch`: the epoch the caller's rights belong to, or DSQ_EPOCH_ANY (server).
// `qlimit`: UINT32_MAX for no limit. `attempts`: 0 for no bound. On DSQ_OK, `*seq_out` (if not NULL)
// is the node's seq. A MAKE_SEND message is a node with DSQ_NODE_MADE_SEND: nothing else is counted here.
int dsq_publish(const dsq_view_t* v, uint32_t slot, uint32_t index, uint32_t epoch, uint32_t qlimit,
		uint32_t attempts, uint32_t* seq_out);

// Finds the node at the head of `slot`'s queue without taking it. On DSQ_OK, `*deq_out` is the deq
// word the caller passes to dsq_take() and `*index_out` the node; any other result has neither.
// `epoch`: the epoch the caller's name table entry belongs to, or DSQ_EPOCH_ANY (server). A slot with
// another epoch (a right of the name changed, or the slot was given to another port) is not the caller's
// queue: DSQ_STALE.
int dsq_head(const dsq_view_t* v, uint32_t slot, uint32_t epoch, uint64_t* deq_out, uint32_t* index_out);

// Takes the head node found by dsq_head() (`deq` is the value it returned). `made_send`: the node's
// DSQ_NODE_MADE_SEND flag, as the caller read it after dsq_head() (the node can't change while deq is
// still `deq`, and the take succeeds only then). The take counts it in the same CAS, so there is no
// moment at which a dequeued MAKE_SEND message is counted nowhere. On success the caller owns the node
// and `*seqno_out` is its seqno.
bool dsq_take(const dsq_view_t* v, uint32_t slot, uint64_t deq, bool made_send, uint32_t* seqno_out);

// The seqno a deq word stands for (the next one the port gives out).
uint32_t dsq_seqno(const dsq_view_t* v, uint32_t slot, uint64_t deq);

// Server only: closes the slot (no publish or take succeeds afterwards) and returns both words as
// they were at that point; the nodes [deq, seq) are then the caller's. Call it once per close: the
// deq word is changed by it, so the values returned are the only record of the queue's last state.
void dsq_close(const dsq_view_t* v, uint32_t slot, uint64_t* head_out, uint64_t* deq_out);

// Server only (no server publish or take on the slot meanwhile): head and deq of an open slot as both
// were at one instant, and the number of MAKE_SEND nodes of the task queued at that instant. It reads
// deq, head, walks the queued nodes and reads deq again; when deq did not change, the pair was the state
// of the queue when head was read, and the nodes it walked were queued (so unchanged) all along.
// DSQ_CONTENDED: the task kept dequeuing for `attempts` rounds; DSQ_CLOSED_Q; DSQ_CORRUPT: a node
// that should be queued is not.
int dsq_snapshot(const dsq_view_t* v, uint32_t slot, uint32_t attempts, uint64_t* head_out,
		uint64_t* deq_out, uint32_t* made_queued_out);

// Server only: collects the nodes [deq, seq) of a closed slot in queue order into `out` (room for
// DSQ_NODES entries). Returns how many it found; a node that can't be found ends the walk.
uint32_t dsq_collect(const dsq_view_t* v, uint32_t slot, uint64_t head, uint64_t deq, uint16_t* out);

// --- node pools ---------------------------------------------------------------------------------

// The task's node allocator (task side). Returns DSQ_NONE when no node is free.
uint32_t dsq_task_node_alloc(const dsq_view_t* v);
void dsq_task_node_free(const dsq_view_t* v, uint32_t index);

// Server only: gives a task node it took back to the task (bounded; false if it gave up).
bool dsq_server_node_return(const dsq_view_t* v, uint32_t index, uint32_t attempts);

// Server only: initializes a new region (both objects are zero-filled).
void dsq_region_init(const dsq_view_t* v);

// Server only: makes `slot` usable for a new port: an empty open queue, the given seqno and a new
// epoch (returned). The previous port of the slot must have been closed. The head's seq (the futex word
// of a receiver) moves on by one, so a receiver that read the previous port's open head and is about to
// wait finds the word changed, whatever the slot did in between.
uint32_t dsq_slot_open(const dsq_view_t* v, uint32_t slot, uint32_t seqno);

// Server only: moves the slot to a new epoch (bounded CAS); false if it would have to wait for T
// (the caller then closes the slot). `*epoch_out` is the new epoch.
bool dsq_slot_bump_epoch(const dsq_view_t* v, uint32_t slot, uint32_t attempts, uint32_t* epoch_out);

// --- name table ---------------------------------------------------------------------------------

// Task side: looks `name` up. Returns false if the name has no shared-mode port (or the table kept
// changing).
bool dsq_name_lookup(const dsq_view_t* v, uint32_t name, dsq_name_entry_t* out);

// Server only (serialized by the caller): adds, changes or removes the entry of `name`.
bool dsq_name_set(const dsq_view_t* v, uint32_t name, uint32_t slot, uint32_t rights, uint32_t epoch);
void dsq_name_remove(const dsq_view_t* v, uint32_t name);

// --- audit token history ---------------------------------------------------------------------------

// Server only (serialized by the caller): makes the given tokens current under a new generation.
void dsq_tokens_push(const dsq_view_t* v, const uint32_t sec_token[2], const uint32_t audit_token[8]);

// Task side: the current generation.
uint32_t dsq_tokens_current(const dsq_view_t* v);

// Task side: the tokens of generation `gen`, or the current ones if it is no longer in the history.
void dsq_tokens_lookup(const dsq_view_t* v, uint32_t gen, uint32_t sec_token[2], uint32_t audit_token[8]);

// --- received messages -----------------------------------------------------------------------------

// The trailer size a receive with `option` gets (REQUESTED_TRAILER_SIZE as darlingserver applies it).
uint32_t dsq_trailer_size(uint32_t option);

// Builds what a receive of the INLINE message in `node` copies out: the header as the server's copyout
// sets it, the body, and the trailer the receive asked for. Returns the number of bytes written to `out`
// (room for DSQ_MSG_MAX + DSQ_TRAILER_MAX).
uint32_t dsq_build_received(const dsq_node_t* node, uint32_t rcv_name, uint32_t option, uint32_t seqno,
		uint64_t context, const uint32_t sec_token[2], const uint32_t audit_token[8], uint8_t* out);

#ifdef __cplusplus
}
#endif

#endif // _DARLINGSERVER_MACH_SQ_H_
