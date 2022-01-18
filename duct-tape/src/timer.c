#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/hooks.h>

#include <kern/timer.h>
#include <kern/timer_call.h>
#include <kern/timer_queue.h>
#include <mach/mach_time.h>

#include <i386/rtclock_protos.h>
#include <i386/pal_native.h>

#define CLOCK_MONOTONIC 1

// copied from glibc's headers
struct timespec
{
  long int tv_sec;		/* Seconds.  */
#if __WORDSIZE == 64 \
  || (defined __SYSCALL_WORDSIZE && __SYSCALL_WORDSIZE == 64) \
  || __TIMESIZE == 32
  long int tv_nsec;	/* Nanoseconds.  */
#else
# if __BYTE_ORDER == __BIG_ENDIAN
  int: 32;           /* Padding.  */
  long int tv_nsec;  /* Nanoseconds.  */
# else
  long int tv_nsec;  /* Nanoseconds.  */
  int: 32;           /* Padding.  */
# endif
#endif
};

int clock_gettime(int clk_id, struct timespec *tp);

// stub
pal_rtc_nanotime_t pal_rtc_nanotime_info;

int master_cpu = 0;

static mpqueue_head_t timer_queue;

uint64_t _rtc_nanotime_read(pal_rtc_nanotime_t* rntp) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
};

void dtape_timer_fired(void) {
	uint64_t next_deadline = timer_queue_expire(&timer_queue, mach_absolute_time());
	dtape_hooks->timer_arm(next_deadline);
};

void timer_call_nosync_cpu(int cpu, void (*fn)(void* arg), void* arg) {
	fn(arg);
};

mpqueue_head_t* timer_queue_assign(uint64_t deadline) {
	dtape_hooks->timer_arm(deadline);
	return &timer_queue;
};

void timer_queue_cancel(mpqueue_head_t* queue, uint64_t deadline, uint64_t new_deadline) {
	dtape_hooks->timer_arm(new_deadline);
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
