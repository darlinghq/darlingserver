#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/waitq.h>
#include <kern/clock.h>
#include <kern/turnstile.h>
#include <kern/thread_call.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <kern/host.h>

#include <sys/types.h>

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
#elif defined(__aarch64__)
	// <copied from="xnu://7195.141.2/osfmk/arm64/status.c"
	unsigned int _MachineStateCount[] = {
		[ARM_UNIFIED_THREAD_STATE] = ARM_UNIFIED_THREAD_STATE_COUNT,
		[ARM_VFP_STATE] = ARM_VFP_STATE_COUNT,
		[ARM_EXCEPTION_STATE] = ARM_EXCEPTION_STATE_COUNT,
		[ARM_DEBUG_STATE] = ARM_DEBUG_STATE_COUNT,
		[ARM_THREAD_STATE64] = ARM_THREAD_STATE64_COUNT,
		[ARM_EXCEPTION_STATE64] = ARM_EXCEPTION_STATE64_COUNT,
		[ARM_THREAD_STATE32] = ARM_THREAD_STATE32_COUNT,
		[ARM_DEBUG_STATE32] = ARM_DEBUG_STATE32_COUNT,
		[ARM_DEBUG_STATE64] = ARM_DEBUG_STATE64_COUNT,
		[ARM_NEON_STATE] = ARM_NEON_STATE_COUNT,
		[ARM_NEON_STATE64] = ARM_NEON_STATE64_COUNT,
		[ARM_PAGEIN_STATE] = ARM_PAGEIN_STATE_COUNT,
	};
	// </copied>
#else
	#error _MachineStateCount not defined on this architecture
#endif

int vsnprintf(char* buffer, size_t buffer_size, const char* format, va_list args);
ssize_t getrandom(void* buf, size_t buflen, unsigned int flags);


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

	dest_pid = ipc_port_get_receiver_task(dest, NULL);

	dtape_log_debug("sending kmsg %p to pid %d", kmsg, dest_pid);
};

void Assert(const char* file, int line, const char* expression) {
	panic("%s:%d Assertion failed: %s", file, line, expression);
};

unsigned int waitq_held(struct waitq* wq) {
	return wq->dtape_waitq_interlock.dtape_interlock.dtape_interlock.dtape_mutex.dtape_owner == (uintptr_t)current_thread();
};

#if __x86_64__ || __aarch64__

//
// <copied from="xnu://7195.141.2/osfmk/x86_64/loose_ends.c">
// <copied from="xnu://7195.141.2/osfmk/arm64/loose_ends.c">
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

#endif

//
// Since this is the only method we need from `bsd_kern.c`, I rather not
// `#ifndef` all of the source code that we don't need in that file.
//
// <copied from="xnu://7195.141.2/osfmk/kern/bsd_kern.c">
//

#ifdef __aarch64__

task_t
get_threadtask(thread_t th)
{
	return th->task;
}

#endif

//
// </copied>
//

// Unlike i386, the preemption methods are not 
// inline for arm. So we will need to create stubs.
#ifdef __aarch64__
int get_preemption_level(void) { return 0; }
void _enable_preemption(void) {}
void _disable_preemption(void) {}
#endif
