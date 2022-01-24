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

int dtape_mach_msg_overwrite(uintptr_t msg, int32_t option, uint32_t send_size, uint32_t rcv_size, uint32_t rcv_name, uint32_t timeout, uint32_t notify, uintptr_t rcv_msg, uint32_t rcv_limit) {
	struct mach_msg_overwrite_trap_args args = {
		.msg = msg,
		.option = option,
		.send_size = send_size,
		.rcv_size = rcv_size,
		.rcv_name = rcv_name,
		.timeout = timeout,
		.priority = notify,
		.rcv_msg = rcv_msg,
		// no rcv_limit
	};
	return mach_msg_overwrite_trap(&args);
};

int dtape_mach_port_deallocate(uint32_t task_name_right, uint32_t port_name_right) {
	struct _kernelrpc_mach_port_deallocate_args args = {
		.target = task_name_right,
		.name = port_name_right,
	};
	return _kernelrpc_mach_port_deallocate_trap(&args);
};
