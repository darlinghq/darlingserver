// the mach eventlink traps for darlingserver's RPC (scripts/generate-rpc-wrappers.py: mach_eventlink_*).
// XNU's (osfmk/ipc/ipc_eventlink.c, built here) do the work; their 64-bit return value (signal count | error << 56)
// goes to the caller's `result`, as the BSD syscall's register value would.
#include <darlingserver/duct-tape/stubs.h>

#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <mach/mach_eventlink_types.h>

extern uint64_t mach_eventlink_signal_trap(mach_port_name_t port, uint64_t signal_count);
extern uint64_t mach_eventlink_wait_until_trap(mach_port_name_t eventlink_port, uint64_t wait_count,
	mach_eventlink_signal_wait_option_t option, kern_clock_id_t clock_id, uint64_t deadline);
extern uint64_t mach_eventlink_signal_wait_until_trap(mach_port_name_t eventlink_port, uint64_t wait_count,
	uint64_t signal_count, mach_eventlink_signal_wait_option_t option, kern_clock_id_t clock_id, uint64_t deadline);
extern int (copyout)(const void* kernel_addr, user_addr_t user_addr, vm_size_t nbytes);

static int put(uint64_t value, uint64_t result) {
	return (copyout)(&value, (user_addr_t)result, sizeof(value)) ? KERN_INVALID_ADDRESS : KERN_SUCCESS;
}

int dtape_mach_eventlink_signal(uint32_t eventlink_port, uint64_t signal_count, uint64_t result) {
	return put(mach_eventlink_signal_trap(eventlink_port, signal_count), result);
}

int dtape_mach_eventlink_wait_until(uint32_t eventlink_port, uint64_t wait_count, uint64_t deadline, uint32_t clock_id,
		uint32_t option, uint64_t result) {
	return put(mach_eventlink_wait_until_trap(eventlink_port, wait_count, option, clock_id, deadline), result);
}

int dtape_mach_eventlink_signal_wait_until(uint32_t eventlink_port, uint64_t wait_count, uint64_t signal_count,
		uint64_t deadline, uint32_t clock_id, uint32_t option, uint64_t result) {
	return put(mach_eventlink_signal_wait_until_trap(eventlink_port, wait_count, signal_count, option, clock_id, deadline), result);
}
