/*
 * ARM64 rtclock implementation for Darling
 *
 * Provides the same clock/time functions as i386/rtclock.c but uses
 * clock_gettime(CLOCK_MONOTONIC) instead of x86 TSC.
 */

#include <mach/mach_types.h>
#include <kern/clock.h>
#include <kern/misc_protos.h>
#include <kern/timer_queue.h>

#define CLOCK_MONOTONIC 1

struct timespec {
	long int tv_sec;
	long int tv_nsec;
};

int clock_gettime(int clk_id, struct timespec *tp);

static uint64_t
rtc_nanotime_read(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static inline uint32_t
_absolutetime_to_microtime(uint64_t abstime, clock_sec_t *secs, clock_usec_t *microsecs)
{
	uint32_t remain;
	*secs = abstime / (uint64_t)NSEC_PER_SEC;
	remain = (uint32_t)(abstime % (uint64_t)NSEC_PER_SEC);
	*microsecs = remain / NSEC_PER_USEC;
	return remain;
}

static inline void
_absolutetime_to_nanotime(uint64_t abstime, clock_sec_t *secs, clock_usec_t *nanosecs)
{
	*secs = abstime / (uint64_t)NSEC_PER_SEC;
	*nanosecs = (clock_usec_t)(abstime % (uint64_t)NSEC_PER_SEC);
}

void
rtc_timer_start(void)
{
	timer_resync_deadlines();
}

int
rtclock_init(void)
{
	return 1;
}

void
clock_get_system_microtime(
	clock_sec_t		*secs,
	clock_usec_t		*microsecs)
{
	uint64_t now = rtc_nanotime_read();
	_absolutetime_to_microtime(now, secs, microsecs);
}

void
clock_get_system_nanotime(
	clock_sec_t		*secs,
	clock_nsec_t		*nanosecs)
{
	uint64_t now = rtc_nanotime_read();
	_absolutetime_to_nanotime(now, secs, nanosecs);
}

void
clock_gettimeofday_set_commpage(uint64_t abstime, uint64_t sec, uint64_t frac, uint64_t scale, uint64_t tick_per_sec)
{
	(void)abstime; (void)sec; (void)frac; (void)scale; (void)tick_per_sec;
}

void
clock_timebase_info(
	mach_timebase_info_t info)
{
	info->numer = info->denom = 1;
}

uint64_t
mach_absolute_time(void)
{
	return rtc_nanotime_read();
}

uint64_t
mach_approximate_time(void)
{
	return rtc_nanotime_read();
}

void
clock_interval_to_absolutetime_interval(
	uint32_t		interval,
	uint32_t		scale_factor,
	uint64_t		*result)
{
	*result = (uint64_t)interval * scale_factor;
}

void
absolutetime_to_microtime(
	uint64_t		abstime,
	clock_sec_t		*secs,
	clock_usec_t		*microsecs)
{
	_absolutetime_to_microtime(abstime, secs, microsecs);
}

void
nanotime_to_absolutetime(
	clock_sec_t		secs,
	clock_nsec_t		nanosecs,
	uint64_t		*result)
{
	*result = ((uint64_t)secs * NSEC_PER_SEC) + nanosecs;
}

void
absolutetime_to_nanoseconds(
	uint64_t		abstime,
	uint64_t		*result)
{
	*result = abstime;
}

void
nanoseconds_to_absolutetime(
	uint64_t		nanoseconds,
	uint64_t		*result)
{
	*result = nanoseconds;
}

void
machine_delay_until(
	uint64_t interval,
	uint64_t deadline)
{
	(void)interval;
	while (mach_absolute_time() < deadline) {
		__asm__ volatile("yield");
	}
}
