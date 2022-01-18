#include <darlingserver/duct-tape.h>

#include <mach/mach_traps.h>

uint32_t dtape_task_self_trap(void) {
	return task_self_trap(NULL);
};

uint32_t dtape_mach_reply_port(void) {
	return mach_reply_port(NULL);
};
