#ifndef _DARLINGSERVER_DUCT_TAPE_TYPES_H_
#define _DARLINGSERVER_DUCT_TAPE_TYPES_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dtape_thread dtape_thread_t;
typedef struct dtape_task dtape_task_t;
typedef struct dtape_kqchan_mach_port dtape_kqchan_mach_port_t;
typedef struct dtape_semaphore dtape_semaphore_t;
typedef uint64_t dtape_eternal_id_t;

typedef enum dtape_log_level {
	dtape_log_level_debug,
	dtape_log_level_info,
	dtape_log_level_warning,
	dtape_log_level_error,
} dtape_log_level_t;

typedef enum dtape_semaphore_wait_result {
	dtape_semaphore_wait_result_error = -1,
	dtape_semaphore_wait_result_ok = 0,
	dtape_semaphore_wait_result_interrupted = 1,
} dtape_semaphore_wait_result_t;

typedef void (*dtape_thread_continuation_callback_f)(void* context);

typedef struct dtape_memory_info {
	uint64_t virtual_size;
	uint64_t resident_size;
	uint64_t page_size;
	uint64_t region_count;
} dtape_memory_info_t;

typedef enum dtape_memory_protection {
	dtape_memory_protection_none = 0,
	dtape_memory_protection_read = 1 << 0,
	dtape_memory_protection_write = 1 << 1,
	dtape_memory_protection_execute = 1 << 2,
} __attribute__((flag_enum)) dtape_memory_protection_t;

typedef struct dtape_memory_region_info {
	uintptr_t start_address;
	uint64_t page_count;
	uint64_t map_offset;
	dtape_memory_protection_t protection;
	bool shared;
} dtape_memory_region_info_t;

typedef enum dtape_memory_flags {
	dtape_memory_flag_none = 0,
	dtape_memory_flag_fixed = 1ULL << 0,
	dtape_memory_flag_overwrite = 1ULL << 1,
} dtape_memory_flags_t;

#if DSERVER_EXTENDED_DEBUG
	typedef uintptr_t dtape_port_id_t;
	typedef uintptr_t dtape_port_set_id_t;
#endif

typedef enum dtape_thread_state {
	dtape_thread_state_dead,
	dtape_thread_state_running,
	dtape_thread_state_stopped,
	dtape_thread_state_interruptible,
	dtape_thread_state_uninterruptible,
} dtape_thread_state_t;

typedef struct dtape_load_info {
	uint64_t task_count;
	uint64_t thread_count;
} dtape_load_info_t;

#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_DUCT_TAPE_TYPES_H_
