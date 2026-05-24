#ifndef _DARLINGSERVER_DUCT_TAPE_LINUX_CLOCK_H_
#define _DARLINGSERVER_DUCT_TAPE_LINUX_CLOCK_H_

// Minimal declaration of the host's clock_gettime(CLOCK_MONOTONIC). duct-tape is
// kernel-side XNU code and can't pull in <time.h> without dragging in conflicting
// Darwin time types, so the timebase sources (timer.c and rtclock_arm64.c)
// historically each redeclared these. Keep the single source of truth here.

#define CLOCK_MONOTONIC 1

// Darling's duct-tape only ever builds for 64-bit Linux hosts (x86_64 / arm64),
// where struct timespec is two longs. Spell it out directly rather than copying
// glibc's __WORDSIZE/__TIMESIZE/endian-conditional definition (which we can't
// pull in via <time.h> here anyway).
struct timespec {
	long tv_sec;
	long tv_nsec;
};

int clock_gettime(int clk_id, struct timespec *tp);

#endif // _DARLINGSERVER_DUCT_TAPE_LINUX_CLOCK_H_
