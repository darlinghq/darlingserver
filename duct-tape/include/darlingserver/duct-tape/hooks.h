#ifndef _DARLINGSERVER_DUCT_TAPE_HOOKS_H_
#define _DARLINGSERVER_DUCT_TAPE_HOOKS_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <libsimple/lock.h>
#include <darlingserver/duct-tape/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef dtape_task_t* (*dtape_hook_current_task_f)(void);
typedef dtape_thread_t* (*dtape_hook_current_thread_f)(void);

/**
 * Arms a timer that should invoke dtape_timer_fired when it expires.
 * The deadline is given as an absolute timepoint with respect to the system's monotonic clock.
 *
 * When called with 0 or UINT64_MAX, the timer should instead be disarmed.
 *
 * Normally, the deadline will only be updated if the given deadline is less than
 * the current deadline (with an exception for 0/UINT64_MAX). If @p override is `true`,
 * this will forcibly update the timer deadline, even if it is later than the current deadline.
 */
typedef void (*dtape_hook_timer_arm_f)(uint64_t absolute_ns, bool override);

typedef void (*dtape_hook_log_f)(dtape_log_level_t level, const char* message);
typedef bool (*dtape_hook_log_enabled_f)(dtape_log_level_t level);
typedef void (*dtape_hook_get_load_info_f)(dtape_load_info_t* load_info);

typedef void (*dtape_hook_thread_suspend_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback, void* continuation_contex, libsimple_lock_t* unlock_me);
typedef void (*dtape_hook_thread_resume_f)(void* thread_context);
typedef void (*dtape_hook_thread_terminate_f)(void* thread_context);
typedef dtape_thread_t* (*dtape_hook_thread_create_kernel_f)(void);
typedef void (*dtape_hook_thread_setup_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback, void* continuation_context);
typedef void (*dtape_hook_thread_set_pending_signal_f)(void* thread_context, int pending_signal);
typedef void (*dtape_hook_thread_set_pending_call_override_f)(void* thread_context, bool pending_call_override);
typedef dtape_thread_t* (*dtape_hook_thread_lookup_f)(int id, bool id_is_nsid, bool retain);
typedef dtape_thread_t* (*dtape_hook_thread_lookup_eternal_f)(dtape_eternal_id_t eid, bool retain);
typedef dtape_thread_state_t (*dtape_hook_thread_get_state_f)(void* thread_context);
typedef bool (*dtape_hook_thread_get_stats_f)(void* thread_context, char* name, size_t name_size, uint64_t* user_time_ns, uint64_t* system_time_ns);
typedef int (*dtape_hook_thread_send_signal_f)(void* thread_context, int signal);
typedef void (*dtape_hook_thread_context_dispose_f)(void* thread_context);
typedef dtape_eternal_id_t (*dtape_hook_thread_eternal_id_f)(void* thread_context);

typedef void (*dtape_hook_current_thread_interrupt_disable_f)(void);
typedef void (*dtape_hook_current_thread_interrupt_enable_f)(void);
typedef void (*dtape_hook_current_thread_syscall_return_f)(int return_code);
typedef void (*dtape_hook_current_thread_set_bsd_retval_f)(uint32_t retval);
// returns whether a wait of the current thread for a server-to-client call was interrupted since the last time this was asked
// (a signal is being delivered to the thread, or it is being suspended or killed), and clears that state
typedef bool (*dtape_hook_current_thread_take_s2c_interrupted_f)(void);
// returns fresh read-write anonymous memory of `length` bytes that an interrupted server-to-client mmap of the current thread
// mapped in its task after the wait for it was abandoned (and forgets it), or 0 if there is none
typedef uintptr_t (*dtape_hook_current_thread_take_stale_mapping_f)(size_t length);

typedef bool (*dtape_hook_task_read_memory_f)(void* task_context, uintptr_t remote_address, void* local_buffer, size_t length);
typedef bool (*dtape_hook_task_write_memory_f)(void* task_context, uintptr_t remote_address, const void* local_buffer, size_t length);
typedef dtape_task_t* (*dtape_hook_task_lookup_f)(int id, bool id_is_nsid, bool retain);
typedef dtape_task_t* (*dtape_hook_task_lookup_eternal_f)(dtape_eternal_id_t eid, bool retain);
// stores the live tasks (oldest first) in `tasks`, each with a reference the caller must drop with dtape_task_release(),
// as long as there is room for them (`capacity` entries), and returns the number of live tasks (which may exceed `capacity`)
typedef size_t (*dtape_hook_task_list_f)(dtape_task_t** tasks, size_t capacity);
typedef bool (*dtape_hook_task_get_memory_info_f)(void* task_context, dtape_memory_info_t* memory_info);
typedef bool (*dtape_hook_task_get_cpu_times_f)(void* task_context, dtape_task_cpu_times_t* cpu_times);
typedef bool (*dtape_hook_task_get_event_counts_f)(void* task_context, dtape_task_event_counts_t* event_counts);
typedef bool (*dtape_hook_task_get_memory_region_info_f)(void* task_context, uintptr_t address, dtape_memory_region_info_t* memory_region_info);
typedef uintptr_t (*dtape_hook_task_allocate_pages_f)(void* task_context, size_t page_count, int protection, uintptr_t address_hint, dtape_memory_flags_t flags);
typedef int (*dtape_hook_task_free_pages_f)(void* task_context, uintptr_t address, size_t page_count);
typedef uintptr_t (*dtape_hook_task_map_file_f)(void* task_context, int fd, size_t page_count, int protection, uintptr_t address_hint, size_t page_offset, dtape_memory_flags_t flags);
typedef bool (*dtape_hook_fd_identity_f)(int fd, uint64_t* device, uint64_t* inode);
typedef uintptr_t (*dtape_hook_task_get_next_region_f)(void* task_context, uintptr_t address);
// counts the resident pages of the region that starts at `start_address`: pages only this task maps, and pages shared with other mappings
typedef bool (*dtape_hook_task_get_region_residency_f)(void* task_context, uintptr_t start_address, uint64_t* private_pages, uint64_t* shared_pages);
typedef bool (*dtape_hook_task_change_protection_f)(void* task_context, uintptr_t address, size_t page_count, int protection);
typedef bool (*dtape_hook_task_sync_memory_f)(void* task_context, uintptr_t address, size_t size, int sync_flags);
typedef void (*dtape_hook_task_context_dispose_f)(void* task_context);
typedef dtape_eternal_id_t (*dtape_hook_task_eternal_id_f)(void* thread_context);

// wakes up to `count` threads waiting (FUTEX_WAIT) on the 32-bit word at `address` in a shared message queue region
typedef void (*dtape_hook_sq_futex_wake_f)(void* address, int count);
// unmaps both objects of a task's shared message queue region (dtape_sq_attach()) once the task is gone
typedef void (*dtape_hook_sq_region_release_f)(void* s_map, size_t s_size, void* q_map, size_t q_size);

typedef enum dtape_task_port_flavor {
	dtape_task_port_flavor_control,
	dtape_task_port_flavor_read,
	dtape_task_port_flavor_inspect,
	dtape_task_port_flavor_name,
} dtape_task_port_flavor_t;

/**
 * Decides whether the task with @p caller_task_context may obtain a task port of the given flavor
 * for the task with @p target_task_context through task_for_pid() or one of its variants.
 */
typedef bool (*dtape_hook_task_port_allowed_f)(void* caller_task_context, void* target_task_context, dtape_task_port_flavor_t flavor);

#if DSERVER_EXTENDED_DEBUG
	typedef void (*dtape_hook_task_register_name_f)(void* task_context, uint32_t name, uintptr_t pointer);
	typedef void (*dtape_hook_task_unregister_name_f)(void* task_context, uint32_t name);
	typedef void (*dtape_hook_task_add_port_set_member_f)(void* task_context, dtape_port_set_id_t port_set, dtape_port_id_t member);
	typedef void (*dtape_hook_task_remove_port_set_member_f)(void* task_context, dtape_port_set_id_t port_set, dtape_port_id_t member);
	typedef void (*dtape_hook_task_clear_port_set_f)(void* task_context, dtape_port_set_id_t port_set);
#endif

typedef struct dtape_hooks {
	dtape_hook_current_task_f current_task;
	dtape_hook_current_thread_f current_thread;

	dtape_hook_timer_arm_f timer_arm;

	dtape_hook_log_f log;
	dtape_hook_log_enabled_f log_enabled;
	dtape_hook_get_load_info_f get_load_info;

	dtape_hook_thread_suspend_f thread_suspend;
	dtape_hook_thread_resume_f thread_resume;
	dtape_hook_thread_terminate_f thread_terminate;
	dtape_hook_thread_create_kernel_f thread_create_kernel;
	dtape_hook_thread_setup_f thread_setup;
	dtape_hook_thread_set_pending_signal_f thread_set_pending_signal;
	dtape_hook_thread_set_pending_call_override_f thread_set_pending_call_override;
	dtape_hook_thread_lookup_f thread_lookup;
	dtape_hook_thread_lookup_eternal_f thread_lookup_eternal;
	dtape_hook_thread_get_state_f thread_get_state;
	dtape_hook_thread_get_stats_f thread_get_stats;
	dtape_hook_thread_send_signal_f thread_send_signal;
	dtape_hook_thread_context_dispose_f thread_context_dispose;
	dtape_hook_thread_eternal_id_f thread_eternal_id;

	dtape_hook_current_thread_interrupt_disable_f current_thread_interrupt_disable;
	dtape_hook_current_thread_interrupt_enable_f current_thread_interrupt_enable;
	dtape_hook_current_thread_syscall_return_f current_thread_syscall_return;
	dtape_hook_current_thread_set_bsd_retval_f current_thread_set_bsd_retval;
	dtape_hook_current_thread_take_s2c_interrupted_f current_thread_take_s2c_interrupted;
	dtape_hook_current_thread_take_stale_mapping_f current_thread_take_stale_mapping;

	dtape_hook_task_read_memory_f task_read_memory;
	dtape_hook_task_write_memory_f task_write_memory;
	dtape_hook_task_lookup_f task_lookup;
	dtape_hook_task_lookup_eternal_f task_lookup_eternal;
	dtape_hook_task_list_f task_list;
	dtape_hook_task_get_memory_info_f task_get_memory_info;
	dtape_hook_task_get_cpu_times_f task_get_cpu_times;
	dtape_hook_task_get_event_counts_f task_get_event_counts;
	dtape_hook_task_get_memory_region_info_f task_get_memory_region_info;
	dtape_hook_task_allocate_pages_f task_allocate_pages;
	dtape_hook_task_free_pages_f task_free_pages;
	dtape_hook_task_map_file_f task_map_file;
	dtape_hook_fd_identity_f fd_identity;
	dtape_hook_task_get_next_region_f task_get_next_region;
	dtape_hook_task_get_region_residency_f task_get_region_residency;
	dtape_hook_task_change_protection_f task_change_protection;
	dtape_hook_task_sync_memory_f task_sync_memory;
	dtape_hook_task_context_dispose_f task_context_dispose;
	dtape_hook_task_eternal_id_f task_eternal_id;
	dtape_hook_task_port_allowed_f task_port_allowed;

	dtape_hook_sq_futex_wake_f sq_futex_wake;
	dtape_hook_sq_region_release_f sq_region_release;

#if DSERVER_EXTENDED_DEBUG
	dtape_hook_task_register_name_f task_register_name;
	dtape_hook_task_unregister_name_f task_unregister_name;
	dtape_hook_task_add_port_set_member_f task_add_port_set_member;
	dtape_hook_task_remove_port_set_member_f task_remove_port_set_member;
	dtape_hook_task_clear_port_set_f task_clear_port_set;
#endif
} dtape_hooks_t;

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_HOOKS_H_
