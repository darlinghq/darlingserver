#ifndef _DARLINGSERVER_DUCT_TAPE_H_
#define _DARLINGSERVER_DUCT_TAPE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <libsimple/lock.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* dtape_thread_handle_t;
typedef void* dtape_task_handle_t;

typedef enum dtape_log_level {
	dtape_log_level_debug,
	dtape_log_level_info,
	dtape_log_level_warning,
	dtape_log_level_error,
} dtape_log_level_t;

typedef void (*dtape_thread_continuation_callback_f)(dtape_thread_handle_t thread);

typedef void (*dtape_hook_thread_suspend_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback, libsimple_lock_t* unlock_me);
typedef void (*dtape_hook_thread_resume_f)(void* thread_context);
typedef dtape_task_handle_t (*dtape_hook_current_task_f)(void);
typedef dtape_thread_handle_t (*dtape_hook_current_thread_f)(void);

/**
 * Arms a timer that should invoke dtape_timer_fired when it expires.
 * The deadline is given as an absolute timepoint with respect to the system's monotonic clock.
 *
 * When called with 0 or UINT64_MAX, the timer should instead be disarmed.
 */
typedef void (*dtape_hook_timer_arm_f)(uint64_t absolute_ns);

typedef void (*dtape_hook_log_f)(dtape_log_level_t level, const char* message);

typedef void (*dtape_hook_thread_terminate_f)(void* thread_context);

typedef dtape_thread_handle_t (*dtape_hook_thread_create_kernel_f)(void);
typedef void (*dtape_hook_thread_start_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback);
typedef void (*dtape_hook_current_thread_interrupt_disable_f)(void);
typedef void (*dtape_hook_current_thread_interrupt_enable_f)(void);
typedef bool (*dtape_hook_task_read_memory_f)(void* task_context, uintptr_t remote_address, void* local_buffer, size_t length);
typedef bool (*dtape_hook_task_write_memory_f)(void* task_context, uintptr_t remote_address, const void* local_buffer, size_t length);

typedef struct dtape_hooks {
	dtape_hook_thread_suspend_f thread_suspend;
	dtape_hook_thread_resume_f thread_resume;
	dtape_hook_current_task_f current_task;
	dtape_hook_current_thread_f current_thread;
	dtape_hook_timer_arm_f timer_arm;
	dtape_hook_log_f log;
	dtape_hook_thread_terminate_f thread_terminate;
	dtape_hook_thread_create_kernel_f thread_create_kernel;
	dtape_hook_thread_start_f thread_start;
	dtape_hook_current_thread_interrupt_disable_f current_thread_interrupt_disable;
	dtape_hook_current_thread_interrupt_enable_f current_thread_interrupt_enable;
	dtape_hook_task_read_memory_f task_read_memory;
	dtape_hook_task_write_memory_f task_write_memory;
} dtape_hooks_t;

void dtape_init(const dtape_hooks_t* hooks);
void dtape_deinit(void);

uint32_t dtape_task_self_trap(void);
uint32_t dtape_host_self_trap(void);
uint32_t dtape_thread_self_trap(void);
uint32_t dtape_mach_reply_port(void);
int dtape_mach_msg_overwrite(uintptr_t msg, int32_t option, uint32_t send_size, uint32_t rcv_size, uint32_t rcv_name, uint32_t timeout, uint32_t notify, uintptr_t rcv_msg, uint32_t rcv_limit);
int dtape_mach_port_deallocate(uint32_t task_name_right, uint32_t port_name_right);

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
#define DTAPE_KERNEL_THREAD_ID_THRESHOLD (1ULL << 44)

/**
 * Creates a new duct-tape task. The caller receives a reference on the new task.
 *
 * An @p nsid value of `0` indicates the task being created is the kernel task.
 */
dtape_task_handle_t dtape_task_create(dtape_task_handle_t parent_task, uint32_t nsid, void* context);
dtape_thread_handle_t dtape_thread_create(dtape_task_handle_t task, uint64_t nsid, void* context);

/**
 * Destroys the given duct-tape task. The caller loses their reference on the task.
 *
 * Additionally, if the caller's reference on the task is not the last reference, this function will abort.
 */
void dtape_task_destroy(dtape_task_handle_t task);
void dtape_thread_destroy(dtape_thread_handle_t thread);

void dtape_thread_entering(dtape_thread_handle_t thread);
void dtape_thread_exiting(dtape_thread_handle_t thread);
void dtape_thread_set_handles(dtape_thread_handle_t thread, uintptr_t pthread_handle, uintptr_t dispatch_qaddr);

void dtape_task_uidgid(dtape_task_handle_t task, int new_uid, int new_gid, int* old_uid, int* old_gid);

/**
 * Invoked when a timer armed by an earlier call to the timer_arm hook expires.
 */
void dtape_timer_fired(void);

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_H_
