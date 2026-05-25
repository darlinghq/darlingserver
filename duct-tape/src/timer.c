#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/hooks.internal.h>

#include <kern/timer.h>
#include <kern/timer_call.h>
#include <kern/timer_queue.h>
#include <mach/mach_time.h>

#if __x86_64__ || __i386__
#include <i386/rtclock_protos.h>
#include <i386/pal_native.h>
#endif

#include "linux_clock.h"

#if __x86_64__ || __i386__
pal_rtc_nanotime_t pal_rtc_nanotime_info;
#endif

int master_cpu = 0;

// convince timer_call code not to use long term timers
int serverperfmode = 1;

static mpqueue_head_t timer_queue;

void dtape_timer_init(void) {
	mpqueue_init(&timer_queue, LCK_GRP_NULL, LCK_ATTR_NULL);
};

#if __x86_64__ || __i386__
uint64_t _rtc_nanotime_read(pal_rtc_nanotime_t* rntp) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
};
#endif

void dtape_timer_fired(void) {
	uint64_t next_deadline = timer_queue_expire(&timer_queue, mach_absolute_time());
	dtape_hooks->timer_arm(next_deadline, true);
};

void timer_call_nosync_cpu(int cpu, void (*fn)(void* arg), void* arg) {
	fn(arg);
};

mpqueue_head_t* timer_queue_assign(uint64_t deadline) {
	dtape_hooks->timer_arm(deadline, false);
	return &timer_queue;
};

void timer_queue_cancel(mpqueue_head_t* queue, uint64_t deadline, uint64_t new_deadline) {
	dtape_hooks->timer_arm(new_deadline, true);
};

mpqueue_head_t* timer_queue_cpu(int cpu) {
	return &timer_queue;
};

// note that in our implementation, we don't need to worry about XNU's running timers.
// those are only used for context switching and kperf.

boolean_t timer_resort_threshold(uint64_t skew) {
	dtape_stub_safe();
	return FALSE;
};

boolean_t ml_timer_forced_evaluation(void) {
	dtape_stub();
	return FALSE;
};

timer_coalescing_priority_params_ns_t* timer_call_get_priority_params(void) {
	static timer_coalescing_priority_params_ns_t params = {0};
	return &params;
}
