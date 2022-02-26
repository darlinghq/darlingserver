#ifndef _DARLINGSERVER_DUCT_TAPE_H_
#define _DARLINGSERVER_DUCT_TAPE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <libsimple/lock.h>
#include <darlingserver/rpc.internal.h>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/rpc.h>

#include <darlingserver/duct-tape/types.h>
#include <darlingserver/duct-tape/hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

void dtape_init(const dtape_hooks_t* hooks);
void dtape_init_in_thread(void);
void dtape_deinit(void);

uint32_t dtape_task_self_trap(void);
uint32_t dtape_host_self_trap(void);
uint32_t dtape_thread_self_trap(void);
uint32_t dtape_mach_reply_port(void);
uint32_t dtape_thread_get_special_reply_port(void);
uint32_t dtape_mk_timer_create(void);

DSERVER_DTAPE_DECLS;

typedef void (*dtape_kqchan_mach_port_notification_callback_f)(void* context);

/**
 * The threshold beyond which thread IDs are considered IDs for kernel threads.
 * Thread IDs lower than this value are reserved for userspace threads.
 * Thread IDs greater than or equal to this value are reserved for kernelspace threads.
 *
 * This should NOT be used to differentiate kernelspace threads from userspace ones.
 * This is simply used as a convenient cutoff beyond which we do not expect Linux to actually assign
 * thread IDs within our namespace. In practice, there should be no difference between the way userspace
 * and kernelspace threads are handled in the duct-tape code.
 *
 * This is used as the starting offset for thread IDs for kernelspace threads (which do not have a "real" managed Darling thread backing them).
 */
#define DTAPE_KERNEL_THREAD_ID_THRESHOLD (1ULL << 22)

/**
 * Creates a new duct-tape task. The caller receives a reference on the new task.
 *
 * An @p nsid value of `0` indicates the task being created is the kernel task.
 */
dtape_task_t* dtape_task_create(dtape_task_t* parent_task, uint32_t nsid, void* context, dserver_rpc_architecture_t architecture);
dtape_thread_t* dtape_thread_create(dtape_task_t* task, uint64_t nsid, void* context);
dtape_kqchan_mach_port_t* dtape_kqchan_mach_port_create(uint32_t port, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, dtape_kqchan_mach_port_notification_callback_f notification_callback, void* context);
dtape_semaphore_t* dtape_semaphore_create(dtape_task_t* owning_task, int initial_value);

/**
 * Destroys the given duct-tape task. The caller loses their reference on the task.
 *
 * Additionally, if the caller's reference on the task is not the last reference, this function will abort.
 */
void dtape_task_destroy(dtape_task_t* task);
void dtape_thread_destroy(dtape_thread_t* thread);
void dtape_kqchan_mach_port_destroy(dtape_kqchan_mach_port_t* kqchan);
void dtape_semaphore_destroy(dtape_semaphore_t* semaphore);

void dtape_thread_entering(dtape_thread_t* thread);
void dtape_thread_exiting(dtape_thread_t* thread);
void dtape_thread_set_handles(dtape_thread_t* thread, uintptr_t pthread_handle, uintptr_t dispatch_qaddr);
/**
 * Returns the thread corresponding to the given thread port.
 *
 * @warning It is VERY important that the caller ensures the thread cannot die while we're looking it up.
 *          This can be accomplished, for example, by locking the global thread list before the call.
 */
dtape_thread_t* dtape_thread_for_port(uint32_t thread_port);
void* dtape_thread_context(dtape_thread_t* thread);
int dtape_thread_load_state_from_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address);
int dtape_thread_save_state_to_user(dtape_thread_t* thread, uintptr_t thread_state_address, uintptr_t float_state_address);
void dtape_thread_process_signal(dtape_thread_t* thread, int bsd_signal_number, int linux_signal_number, int code, uintptr_t signal_address);
void dtape_thread_wait_while_user_suspended(dtape_thread_t* thread);
void dtape_thread_retain(dtape_thread_t* thread);
void dtape_thread_release(dtape_thread_t* thread);

void dtape_task_uidgid(dtape_task_t* task, int new_uid, int new_gid, int* old_uid, int* old_gid);
void dtape_task_retain(dtape_task_t* task);
void dtape_task_release(dtape_task_t* task);

/**
 * Invoked when a timer armed by an earlier call to the timer_arm hook expires.
 */
void dtape_timer_fired(void);

void dtape_kqchan_mach_port_modify(dtape_kqchan_mach_port_t* kqchan, uint64_t receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags);
void dtape_kqchan_mach_port_disable_notifications(dtape_kqchan_mach_port_t* kqchan);
bool dtape_kqchan_mach_port_fill(dtape_kqchan_mach_port_t* kqchan, dserver_kqchan_reply_mach_port_read_t* reply, uint64_t default_buffer, uint64_t default_buffer_size);
bool dtape_kqchan_mach_port_has_events(dtape_kqchan_mach_port_t* kqchan);

void dtape_semaphore_up(dtape_semaphore_t* semaphore);
dtape_semaphore_wait_result_t dtape_semaphore_down(dtape_semaphore_t* semaphore);
bool dtape_semaphore_down_simple(dtape_semaphore_t* semaphore);

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_H_
