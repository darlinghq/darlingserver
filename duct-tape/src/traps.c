#include <darlingserver/duct-tape.h>

#include <mach/mach_traps.h>

uint32_t dtape_task_self_trap(void) {
	return task_self_trap(NULL);
};

uint32_t dtape_host_self_trap(void) {
	return host_self_trap(NULL);
};

uint32_t dtape_thread_self_trap(void) {
	return thread_self_trap(NULL);
};

uint32_t dtape_mach_reply_port(void) {
	return mach_reply_port(NULL);
};

uint32_t dtape_thread_get_special_reply_port(void) {
	return thread_get_special_reply_port(NULL);
};

uint32_t dtape_mk_timer_create(void) {
	return mk_timer_create_trap(NULL);
};

DSERVER_DTAPE_DEFS;
