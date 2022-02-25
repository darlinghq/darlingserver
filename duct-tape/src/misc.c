#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/hooks.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/processor.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/psynch.h>

#include <kern/waitq.h>
#include <kern/clock.h>
#include <kern/turnstile.h>
#include <kern/thread_call.h>
#include <ipc/ipc_init.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <kern/host.h>
#include <kern/sync_sema.h>
#include <kern/ux_handler.h>
#include <ipc/ipc_importance.h>

#include <sys/types.h>

const dtape_hooks_t* dtape_hooks;
char version[] = "Darling 11.5";

#if __x86_64__ || __i386__
	// <copied from="xnu://7195.141.2/osfmk/i386/pcb.c"
	unsigned int _MachineStateCount[] = {
		[x86_THREAD_STATE32]            = x86_THREAD_STATE32_COUNT,
		[x86_THREAD_STATE64]            = x86_THREAD_STATE64_COUNT,
		[x86_THREAD_FULL_STATE64]       = x86_THREAD_FULL_STATE64_COUNT,
		[x86_THREAD_STATE]              = x86_THREAD_STATE_COUNT,
		[x86_FLOAT_STATE32]             = x86_FLOAT_STATE32_COUNT,
		[x86_FLOAT_STATE64]             = x86_FLOAT_STATE64_COUNT,
		[x86_FLOAT_STATE]               = x86_FLOAT_STATE_COUNT,
		[x86_EXCEPTION_STATE32]         = x86_EXCEPTION_STATE32_COUNT,
		[x86_EXCEPTION_STATE64]         = x86_EXCEPTION_STATE64_COUNT,
		[x86_EXCEPTION_STATE]           = x86_EXCEPTION_STATE_COUNT,
		[x86_DEBUG_STATE32]             = x86_DEBUG_STATE32_COUNT,
		[x86_DEBUG_STATE64]             = x86_DEBUG_STATE64_COUNT,
		[x86_DEBUG_STATE]               = x86_DEBUG_STATE_COUNT,
		[x86_AVX_STATE32]               = x86_AVX_STATE32_COUNT,
		[x86_AVX_STATE64]               = x86_AVX_STATE64_COUNT,
		[x86_AVX_STATE]                 = x86_AVX_STATE_COUNT,
		[x86_AVX512_STATE32]            = x86_AVX512_STATE32_COUNT,
		[x86_AVX512_STATE64]            = x86_AVX512_STATE64_COUNT,
		[x86_AVX512_STATE]              = x86_AVX512_STATE_COUNT,
		[x86_PAGEIN_STATE]              = x86_PAGEIN_STATE_COUNT
	};
	// </copied>
#else
	#error _MachineStateCount not defined on this architecture
#endif

int vsnprintf(char* buffer, size_t buffer_size, const char* format, va_list args);
ssize_t getrandom(void* buf, size_t buflen, unsigned int flags);

void ipc_table_init(void);
void ipc_init(void);
void mig_init(void);
void host_notify_init(void);
void user_data_attr_manager_init(void);
void ipc_voucher_init(void);

void dtape_timer_init(void);

extern zone_t semaphore_zone;
extern lck_spin_t ipc_importance_lock_data;
extern zone_t ipc_importance_task_zone;
extern zone_t ipc_importance_inherit_zone;

void dtape_logv(dtape_log_level_t level, const char* format, va_list args) {
	char message[4096];
	vsnprintf(message, sizeof(message), format, args);
	dtape_hooks->log(level, message);
};

void dtape_log(dtape_log_level_t level, const char* format, ...) {
	va_list args;
	va_start(args, format);
	dtape_logv(level, format, args);
	va_end(args);
};

void dtape_init(const dtape_hooks_t* hooks) {
	dtape_hooks = hooks;

	dtape_log_debug("dtape_processor_init");
	dtape_processor_init();

	dtape_log_debug("dtape_memory_init");
	dtape_memory_init();

	ipc_space_zone = zone_create("ipc spaces", sizeof(struct ipc_space), ZC_NOENCRYPT);
	ipc_kmsg_zone = zone_create("ipc kmsgs", IKM_SAVED_KMSG_SIZE, ZC_CACHING | ZC_ZFREE_CLEARMEM);
	semaphore_zone = zone_create("semaphores", sizeof(struct semaphore), ZC_NONE);

	ipc_object_zones[IOT_PORT] = zone_create("ipc ports", sizeof(struct ipc_port), ZC_NOENCRYPT | ZC_CACHING | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);
	ipc_object_zones[IOT_PORT_SET] = zone_create("ipc port sets", sizeof(struct ipc_pset), ZC_NOENCRYPT | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);

	ipc_importance_task_zone = zone_create("ipc task importance", sizeof(struct ipc_importance_task), ZC_NOENCRYPT);
	ipc_importance_inherit_zone = zone_create("ipc importance inherit", sizeof(struct ipc_importance_inherit), ZC_NOENCRYPT);

	lck_mtx_init(&realhost.lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	lck_spin_init(&ipc_importance_lock_data, LCK_GRP_NULL, LCK_ATTR_NULL);

	dtape_timer_init();

	dtape_log_debug("timer_call_init");
	timer_call_init();

	dtape_log_debug("ipc_table_init");
	ipc_table_init();

	dtape_log_debug("ipc_voucher_init");
	ipc_voucher_init();

	dtape_log_debug("dtape_task_init");
	dtape_task_init();

	dtape_log_debug("ipc_init");
	ipc_init();

	dtape_log_debug("mig_init");
	mig_init();

	dtape_log_debug("host_notify_init");
	host_notify_init();

	dtape_log_debug("user_data_attr_manager_init");
	user_data_attr_manager_init();

	dtape_log_debug("waitq_bootstrap");
	waitq_bootstrap();

	dtape_log_debug("clock_init");
	clock_init();

	dtape_log_debug("turnstiles_init");
	turnstiles_init();
};

void dtape_init_in_thread(void) {
	dtape_log_debug("thread_call_initialize");
	thread_call_initialize();

	dtape_log_debug("ipc_thread_call_init");
	ipc_thread_call_init();

	dtape_log_debug("clock_service_create");
	clock_service_create();

	dtape_log_debug("thread_deallocate_daemon_init");
	thread_deallocate_daemon_init();

	ux_handler_init();
	ux_handler_setup();

	dtape_psynch_init();
};

void dtape_deinit(void) {

};

void read_frandom(void* buffer, unsigned int numBytes) {
	getrandom(buffer, numBytes, 0);
};

void kprintf(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	dtape_logv(dtape_log_level_info, fmt, args);
	va_end(args);
};

int scnprintf(char* buffer, size_t buffer_size, const char* format, ...) {
	va_list args;
	va_start(args, format);
	int code = vsnprintf(buffer, buffer_size, format, args);
	va_end(args);
	if (code < 0) {
		return code;
	} else {
		return strnlen(buffer, buffer_size);
	}
};

void (ipc_kmsg_trace_send)(ipc_kmsg_t kmsg, mach_msg_option_t option) {
	pid_t dest_pid = -1;
	ipc_port_t dest = kmsg->ikm_header->msgh_remote_port;

	ip_lock(dest);
	if (dest && ip_active(dest)) {
		ipc_space_t space = dest->ip_receiver;
		if (space && is_active(space)) {
			dest_pid = task_pid(space->is_task);
		}
	}
	ip_unlock(dest);

	dtape_log_debug("sending kmsg %p to pid %d", kmsg, dest_pid);
};

void Assert(const char* file, int line, const char* expression) {
	panic("%s:%d Assertion failed: %s", file, line, expression);
};

unsigned int waitq_held(struct waitq* wq) {
	return wq->dtape_waitq_interlock.dtape_interlock.dtape_interlock.dtape_mutex->dtape_owner == (uintptr_t)current_thread();
};

#if __x86_64__

//
// <copied from="xnu://7195.141.2/osfmk/x86_64/loose_ends.c">
//

/*
 * Find last bit set in bit string.
 */
int
fls(unsigned int mask)
{
	if (mask == 0) {
		return 0;
	}

	return (sizeof(mask) << 3) - __builtin_clz(mask);
}

//
// </copied>
//

#endif
