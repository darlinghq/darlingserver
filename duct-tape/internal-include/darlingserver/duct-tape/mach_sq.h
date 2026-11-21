#ifndef _DARLINGSERVER_DUCT_TAPE_MACH_SQ_H_
#define _DARLINGSERVER_DUCT_TAPE_MACH_SQ_H_

// darlingserver's side of shared message queues (darlingserver/mach-sq.h): which ports use one,
// delivery to and receipt from them in the server, and taking a port out of the mode.
// The functions are called from XNU's ipc code at the points named below.

#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/port.h>

struct ipc_port;
struct ipc_mqueue;
struct ipc_kmsg;
struct ipc_space;
struct ipc_entry;
struct thread;
struct dtape_task;

// a receive right was just created with mach_port_allocate() or mach_port_construct().
// puts the port in shared-queue mode if the space is the current task's, the task has a region,
// and the port is a plain one. nothing locked
void dtape_sq_port_created(struct ipc_space* space, mach_port_name_t name);

// takes the port out of shared-queue mode, if it is in it: its queued messages move to its ipc_mqueue
// (in order, with the seqno and make-send count they imply) and its local waiters are woken.
// `reason` is a DSQ_CLOSE_* value. port locked, mqueue not locked
void dtape_sq_port_leave(struct ipc_port* port, uint32_t reason);

// the same with the port and its mqueue locked
void dtape_sq_port_leave_locked(struct ipc_port* port, uint32_t reason);

// ipc_entry_modified(): the rights of an entry changed. space write-locked
void dtape_sq_entry_modified(struct ipc_space* space, mach_port_name_t name, struct ipc_entry* entry);

// the port's context (ip_context) changed. port locked
void dtape_sq_port_context_changed(struct ipc_port* port);

// the port's qlimit changed. mqueue locked
void dtape_sq_port_qlimit_changed(struct ipc_port* port);

// ipc_kmsg_send() to a port, before ipc_mqueue_send(). port and mqueue locked.
// returns true when it has dealt with the message (both unlocked, `*mrp` set); false when the caller
// continues as for any other port (both still locked; the port is no longer in the mode)
boolean_t dtape_sq_mqueue_send(struct ipc_port* port, struct ipc_kmsg* kmsg, mach_msg_option_t option,
    mach_msg_timeout_t send_timeout, mach_msg_return_t* mrp);

// ipc_mqueue_receive() on a port. nothing locked.
// returns true when it has received (the thread's ith_* receive state set, as ipc_mqueue_receive_on_thread()
// leaves it); false when the caller receives as for any other port
boolean_t dtape_sq_mqueue_receive(struct ipc_mqueue* mqueue, mach_msg_option_t option, mach_msg_size_t max_size,
    mach_msg_timeout_t rcv_timeout, struct thread* thread);

// mach_port_get_status_helper(): the counts of a port's queue as XNU would report them, all from one
// instant of the shared queue; if the task keeps its queue too busy for that (or the queue is closed
// already), the port leaves the mode and the counts are the port's own. port locked, mqueue not locked
void dtape_sq_port_status(struct ipc_port* port, mach_port_status_t* status);

// the number of messages queued on a port (for darlingserver's debug listings). nothing locked
mach_port_msgcount_t dtape_sq_port_message_count(struct ipc_port* port);

// the task's audit or security token changed
void dtape_sq_task_tokens_changed(struct dtape_task* task);

// the task is being destroyed (its space has been terminated): frees its region
void dtape_sq_task_destroy(struct dtape_task* task);

#endif // _DARLINGSERVER_DUCT_TAPE_MACH_SQ_H_
