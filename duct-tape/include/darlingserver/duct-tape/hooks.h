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
typedef void (*dtape_hook_get_load_info_f)(dtape_load_info_t* load_info);

typedef void (*dtape_hook_thread_suspend_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback, void* continuation_contex, libsimple_lock_t* unlock_me);
typedef void (*dtape_hook_thread_resume_f)(void* thread_context);
typedef void (*dtape_hook_thread_terminate_f)(void* thread_context);
typedef dtape_thread_t* (*dtape_hook_thread_create_kernel_f)(void);
typedef void (*dtape_hook_thread_setup_f)(void* thread_context, dtape_thread_continuation_callback_f continuation_callback, void* continuation_context);
typedef void (*dtape_hook_thread_set_pending_signal_f)(void* thread_context, int pending_signal);
typedef void (*dtape_hook_thread_set_pending_call_override_f)(void* thread_context, bool pending_call_override);
typedef dtape_thread_t* (*dtape_hook_thread_lookup_f)(int id, bool id_is_nsid, bool retain);
typedef dtape_thread_state_t (*dtape_hook_thread_get_state_f)(void* thread_context);
typedef int (*dtape_hook_thread_send_signal_f)(void* thread_context, int signal);
typedef void (*dtape_hook_thread_context_dispose_f)(void* thread_context);

typedef void (*dtape_hook_current_thread_interrupt_disable_f)(void);
typedef void (*dtape_hook_current_thread_interrupt_enable_f)(void);
typedef void (*dtape_hook_current_thread_syscall_return_f)(int return_code);
typedef void (*dtape_hook_current_thread_set_bsd_retval_f)(uint32_t retval);

typedef bool (*dtape_hook_task_read_memory_f)(void* task_context, uintptr_t remote_address, void* local_buffer, size_t length);
typedef bool (*dtape_hook_task_write_memory_f)(void* task_context, uintptr_t remote_address, const void* local_buffer, size_t length);
typedef dtape_task_t* (*dtape_hook_task_lookup_f)(int id, bool id_is_nsid, bool retain);
typedef void (*dtape_hook_task_get_memory_info_f)(void* task_context, dtape_memory_info_t* memory_info);
typedef bool (*dtape_hook_task_get_memory_region_info_f)(void* task_context, uintptr_t address, dtape_memory_region_info_t* memory_region_info);
typedef uintptr_t (*dtape_hook_task_allocate_pages_f)(void* task_context, size_t page_count, int protection, uintptr_t address_hint, dtape_memory_flags_t flags);
typedef int (*dtape_hook_task_free_pages_f)(void* task_context, uintptr_t address, size_t page_count);
typedef uintptr_t (*dtape_hook_task_map_file_f)(void* task_context, int fd, size_t page_count, int protection, uintptr_t address_hint, size_t page_offset, dtape_memory_flags_t flags);
typedef uintptr_t (*dtape_hook_task_get_next_region_f)(void* task_context, uintptr_t address);
typedef bool (*dtape_hook_task_change_protection_f)(void* task_context, uintptr_t address, size_t page_count, int protection);
typedef bool (*dtape_hook_task_sync_memory_f)(void* task_context, uintptr_t address, size_t size, int sync_flags);
typedef void (*dtape_hook_task_context_dispose_f)(void* task_context);

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
	dtape_hook_get_load_info_f get_load_info;

	dtape_hook_thread_suspend_f thread_suspend;
	dtape_hook_thread_resume_f thread_resume;
	dtape_hook_thread_terminate_f thread_terminate;
	dtape_hook_thread_create_kernel_f thread_create_kernel;
	dtape_hook_thread_setup_f thread_setup;
	dtape_hook_thread_set_pending_signal_f thread_set_pending_signal;
	dtape_hook_thread_set_pending_call_override_f thread_set_pending_call_override;
	dtape_hook_thread_lookup_f thread_lookup;
	dtape_hook_thread_get_state_f thread_get_state;
	dtape_hook_thread_send_signal_f thread_send_signal;
	dtape_hook_thread_context_dispose_f thread_context_dispose;

	dtape_hook_current_thread_interrupt_disable_f current_thread_interrupt_disable;
	dtape_hook_current_thread_interrupt_enable_f current_thread_interrupt_enable;
	dtape_hook_current_thread_syscall_return_f current_thread_syscall_return;
	dtape_hook_current_thread_set_bsd_retval_f current_thread_set_bsd_retval;

	dtape_hook_task_read_memory_f task_read_memory;
	dtape_hook_task_write_memory_f task_write_memory;
	dtape_hook_task_lookup_f task_lookup;
	dtape_hook_task_get_memory_info_f task_get_memory_info;
	dtape_hook_task_get_memory_region_info_f task_get_memory_region_info;
	dtape_hook_task_allocate_pages_f task_allocate_pages;
	dtape_hook_task_free_pages_f task_free_pages;
	dtape_hook_task_map_file_f task_map_file;
	dtape_hook_task_get_next_region_f task_get_next_region;
	dtape_hook_task_change_protection_f task_change_protection;
	dtape_hook_task_sync_memory_f task_sync_memory;
	dtape_hook_task_context_dispose_f task_context_dispose;

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
