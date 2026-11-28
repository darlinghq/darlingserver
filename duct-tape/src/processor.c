#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/hooks.internal.h>

#include <kern/processor.h>
#include <kern/kalloc.h>
#include <kern/host.h>
#include <kern/machine.h>

#include <darlingserver/duct-tape/processor.h>
#include <darlingserver/duct-tape/task.h>

processor_t processor_array[MAX_SCHED_CPUS] = {0};
struct processor_set pset0;

// don't use these in our code; this is only for XNU code
// use get_nprocs() instead.
uint32_t processor_avail_count;
uint32_t processor_avail_count_user;

// ditto
uint32_t primary_processor_avail_count;
uint32_t primary_processor_avail_count_user;

unsigned int processor_count;

simple_lock_data_t processor_list_lock;
processor_t master_processor;

// Linux functions
int get_nprocs(void);
int get_nprocs_conf(void);

// Linux file access
int open(const char* path, int flags, ...);
long read(int fd, void* buffer, unsigned long count);
int close(int fd);
#define LINUX_O_RDONLY 0
#define LINUX_O_CLOEXEC 02000000

// reads an unsigned decimal number, skipping the blanks in front of it; returns NULL if there is none
static const char* parse_stat_number(const char* ptr, const char* end, uint64_t* value) {
	*value = 0;
	while (ptr < end && *ptr == ' ') {
		++ptr;
	}
	if (ptr >= end || *ptr < '0' || *ptr > '9') {
		return NULL;
	}
	while (ptr < end && *ptr >= '0' && *ptr <= '9') {
		*value = (*value * 10) + (*ptr - '0');
		++ptr;
	}
	return ptr;
};

// interprets a "cpu" line of /proc/stat of Linux: its fields are, in USER_HZ (1/100 s) units, the time spent in
// user mode (which includes guest time), niced user mode, kernel mode, idle, waiting for I/O, interrupt handlers,
// soft interrupt handlers and stolen by a hypervisor. there is no I/O wait or steal state on macOS: that time is
// time the CPU was not running anything for this system, which is idle.
static bool parse_cpu_stat_line(const char* ptr, const char* end, uint32_t ticks[4]) {
	uint64_t field[8] = {0};

	for (size_t i = 0; i < 8; ++i) {
		ptr = parse_stat_number(ptr, end, &field[i]);
		if (!ptr) {
			// the later fields are missing on old kernels
			if (i < 4) {
				return false;
			}
			break;
		}
	}

	ticks[CPU_STATE_USER] = (uint32_t)field[0];
	ticks[CPU_STATE_NICE] = (uint32_t)field[1];
	ticks[CPU_STATE_SYSTEM] = (uint32_t)(field[2] + field[5] + field[6]);
	ticks[CPU_STATE_IDLE] = (uint32_t)(field[3] + field[4] + field[7]);
	return true;
};

bool dtape_cpu_load_ticks(int cpu, uint32_t ticks[4]) {
	char buffer[4096];
	size_t used = 0;
	bool found = false;
	bool eof = false;
	int fd = open("/proc/stat", LINUX_O_RDONLY | LINUX_O_CLOEXEC);

	if (fd < 0) {
		return false;
	}

	while (!found && (!eof || used > 0)) {
		char* newline = NULL;

		for (size_t i = 0; i < used; ++i) {
			if (buffer[i] == '\n') {
				newline = &buffer[i];
				break;
			}
		}

		if (!newline && !eof && used < sizeof(buffer)) {
			long result = read(fd, buffer + used, sizeof(buffer) - used);
			if (result <= 0) {
				eof = true;
			} else {
				used += result;
			}
			continue;
		}

		size_t length = newline ? (size_t)(newline - buffer) : used;

		if (length > 3 && buffer[0] == 'c' && buffer[1] == 'p' && buffer[2] == 'u') {
			const char* ptr = buffer + 3;
			const char* end = buffer + length;
			bool matches = false;

			if (cpu < 0) {
				matches = *ptr == ' ';
			} else if (*ptr >= '0' && *ptr <= '9') {
				uint64_t number;
				ptr = parse_stat_number(ptr, end, &number);
				matches = ptr && number == (uint64_t)cpu;
			}

			if (matches) {
				found = parse_cpu_stat_line(ptr, end, ticks);
				break;
			}
		}

		// drop the line (or, if it did not fit in the buffer, what we have of it)
		size_t consumed = newline ? length + 1 : used;
		memmove(buffer, buffer + consumed, used - consumed);
		used -= consumed;
	}

	close(fd);
	return found;
};

void dtape_processor_init(void) {
	simple_lock_init(&processor_list_lock, 0);

	processor_count = get_nprocs_conf();
	if (processor_count > MAX_SCHED_CPUS)
		processor_count = MAX_SCHED_CPUS;

	processor_avail_count = get_nprocs();
	if (processor_avail_count > MAX_SCHED_CPUS)
		processor_avail_count = MAX_SCHED_CPUS;

	processor_avail_count_user = processor_avail_count;
	primary_processor_avail_count = processor_avail_count;
	primary_processor_avail_count_user = processor_avail_count;

	for (size_t i = 0; i < processor_count; ++i) {
		processor_t processor = NULL;

		processor = kalloc(sizeof(*processor));
		processor_array[i] = processor;

		memset(processor, 0, sizeof(*processor));

		processor->processor_set = &pset0;
		processor->cpu_id = i;
	}

	pset0.online_processor_count = processor_avail_count;

	master_processor = processor_array[0];

	// TODO: there's probably more stuff we should set in these structures
};

kern_return_t processor_assign(processor_t processor, processor_set_t new_pset, boolean_t wait) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t processor_control(processor_t processor, processor_info_t info, mach_msg_type_number_t count) {
	// guest-reachable through MIG.
	// XNU: cpu_control(), which no x86 platform implements.
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_FAILURE;
};

kern_return_t processor_exit_from_user(processor_t processor) {
	// guest-reachable through MIG.
	// Linux CPUs are not taken offline from a container (XNU: !ml_cpu_can_exit()).
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_NOT_SUPPORTED;
};

kern_return_t processor_get_assignment(processor_t processor, processor_set_t* pset) {
	// guest-reachable through MIG.
	// XNU: every online processor is in pset0.
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	*pset = &pset0;
	return KERN_SUCCESS;
};

kern_return_t processor_info(processor_t processor, processor_flavor_t flavor, host_t* host, processor_info_t raw_info, mach_msg_type_number_t* count) {
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
		case PROCESSOR_BASIC_INFO: {
			processor_basic_info_t info = (void*)raw_info;

			if (*count < PROCESSOR_BASIC_INFO_COUNT) {
				return KERN_FAILURE;
			}

#if __x86_64__ || __i386__
			info->cpu_type = CPU_TYPE_X86;
#if __x86_64__
			info->cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
#else
			info->cpu_subtype = CPU_SUBTYPE_I386_ALL;
#endif
#elif __aarch64__
			info->cpu_type = CPU_TYPE_ARM64;
			info->cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
#else
			#error Unknown CPU type
#endif

			info->is_master = processor == master_processor;
			info->running = TRUE;
			info->slot_num = processor->cpu_id;

			*count = PROCESSOR_BASIC_INFO_COUNT;
			*host = &realhost;

			return KERN_SUCCESS;
		};

		case PROCESSOR_CPU_LOAD_INFO: {
			processor_cpu_load_info_t info = (void*)raw_info;

			if (*count < PROCESSOR_CPU_LOAD_INFO_COUNT) {
				return KERN_FAILURE;
			}

			uint32_t ticks[4];

			if (!dtape_cpu_load_ticks(processor->cpu_id, ticks)) {
				return KERN_FAILURE;
			}

			info->cpu_ticks[CPU_STATE_USER] = ticks[CPU_STATE_USER];
			info->cpu_ticks[CPU_STATE_SYSTEM] = ticks[CPU_STATE_SYSTEM];
			info->cpu_ticks[CPU_STATE_IDLE] = ticks[CPU_STATE_IDLE];
			info->cpu_ticks[CPU_STATE_NICE] = ticks[CPU_STATE_NICE];

			*count = PROCESSOR_CPU_LOAD_INFO_COUNT;
			*host = &realhost;

			return KERN_SUCCESS;
		};

		default:
			return KERN_FAILURE;
	}
};

kern_return_t processor_set_create(host_t host, processor_set_t* new_set, processor_set_t* new_name) {
	// guest-reachable through MIG.
	// XNU: there is only pset0.
	return KERN_FAILURE;
};

kern_return_t processor_set_destroy(processor_set_t pset) {
	// guest-reachable through MIG.
	// XNU: pset0 is never destroyed.
	return KERN_FAILURE;
};

kern_return_t processor_set_max_priority(processor_set_t pset, int max_priority, boolean_t change_threads) {
	// guest-reachable through MIG.
	// XNU: obsolete.
	return KERN_INVALID_ARGUMENT;
};

kern_return_t processor_set_policy_control(processor_set_t pset, int flavor, processor_set_info_t policy_info, mach_msg_type_number_t count, boolean_t change) {
	// guest-reachable through MIG.
	// XNU: obsolete.
	return KERN_INVALID_ARGUMENT;
};

kern_return_t processor_set_policy_disable(processor_set_t pset, int policy, boolean_t change_threads) {
	// guest-reachable through MIG.
	// XNU: obsolete.
	return KERN_INVALID_ARGUMENT;
};

kern_return_t processor_set_policy_enable(processor_set_t pset, int policy) {
	// guest-reachable through MIG.
	// XNU: obsolete.
	return KERN_INVALID_ARGUMENT;
};

kern_return_t processor_set_stack_usage(processor_set_t pset, unsigned int* totalp, vm_size_t* spacep, vm_size_t* residentp, vm_size_t* maxusagep, vm_offset_t* maxstackp) {
	// guest-reachable through MIG.
	// XNU without MACH_DEBUG.
	return KERN_NOT_SUPPORTED;
};

kern_return_t processor_set_statistics(processor_set_t pset, int flavor, processor_set_info_t raw_info, mach_msg_type_number_t* count) {
	if (pset == PROCESSOR_SET_NULL || pset != &pset0) {
		return KERN_INVALID_PROCESSOR_SET;
	}

	switch (flavor) {
		case PROCESSOR_SET_LOAD_INFO: {
			processor_set_load_info_t info = (void*)raw_info;
			dtape_load_info_t load_info;

			if (*count < PROCESSOR_SET_LOAD_INFO_COUNT) {
				return KERN_FAILURE;
			}

			info->mach_factor = 0;
			info->load_average = 0;

			dtape_hooks->get_load_info(&load_info);
			info->task_count = load_info.task_count;
			info->thread_count = load_info.thread_count;

			*count = PROCESSOR_SET_LOAD_INFO_COUNT;

			return KERN_SUCCESS;
		};

		default:
			return KERN_INVALID_ARGUMENT;
	}
};

// returns, in `task_list`, a port of the requested flavor for each task of the system that the caller may
// obtain such a port for (the same decision task_for_pid() and its siblings make for that task)
static kern_return_t processor_set_tasks_internal(processor_set_t pset, task_array_t* task_list, mach_msg_type_number_t* count, mach_task_flavor_t flavor) {
	dtape_task_port_flavor_t hook_flavor;
	dtape_task_t** tasks = NULL;
	size_t capacity = 0;
	size_t actual = 0;
	size_t used = 0;
	size_t size_needed;
	ipc_port_t* ports;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
		case TASK_FLAVOR_CONTROL:
			hook_flavor = dtape_task_port_flavor_control;
			break;
		case TASK_FLAVOR_READ:
			hook_flavor = dtape_task_port_flavor_read;
			break;
		case TASK_FLAVOR_INSPECT:
			hook_flavor = dtape_task_port_flavor_inspect;
			break;
		case TASK_FLAVOR_NAME:
			hook_flavor = dtape_task_port_flavor_name;
			break;
		default:
			return KERN_INVALID_ARGUMENT;
	}

	// tasks may be created between asking for their number and getting the list, so ask until there was room for all
	for (;;) {
		actual = dtape_hooks->task_list(tasks, capacity);
		if (actual <= capacity) {
			break;
		}

		if (tasks) {
			kfree(tasks, capacity * sizeof(*tasks));
		}

		capacity = actual + 8;
		tasks = kalloc(capacity * sizeof(*tasks));
		if (!tasks) {
			return KERN_RESOURCE_SHORTAGE;
		}
	}

	if (actual == 0) {
		if (tasks) {
			kfree(tasks, capacity * sizeof(*tasks));
		}
		*task_list = NULL;
		*count = 0;
		return KERN_SUCCESS;
	}

	// keep only the tasks the caller may get a port for
	for (size_t i = 0; i < actual; ++i) {
		if (dtape_hooks->task_port_allowed(dtape_task_for_xnu_task(current_task())->context, tasks[i]->context, hook_flavor)) {
			tasks[used++] = tasks[i];
		} else {
			dtape_task_release(tasks[i]);
		}
	}

	if (used == 0) {
		kfree(tasks, capacity * sizeof(*tasks));
		*task_list = NULL;
		*count = 0;
		return KERN_SUCCESS;
	}

	size_needed = used * sizeof(ipc_port_t);
	ports = kalloc(size_needed);
	if (!ports) {
		for (size_t i = 0; i < used; ++i) {
			dtape_task_release(tasks[i]);
		}
		kfree(tasks, capacity * sizeof(*tasks));
		return KERN_RESOURCE_SHORTAGE;
	}

	// the conversions consume the references
	for (size_t i = 0; i < used; ++i) {
		task_t task = &tasks[i]->xnu_task;

		switch (flavor) {
			case TASK_FLAVOR_CONTROL:
				if (task == current_task()) {
					ports[i] = convert_task_to_port_pinned(task);
				} else {
					ports[i] = convert_task_to_port(task);
				}
				break;
			case TASK_FLAVOR_READ:
				ports[i] = convert_task_read_to_port(task);
				break;
			case TASK_FLAVOR_INSPECT:
				ports[i] = convert_task_inspect_to_port(task);
				break;
			default:
				ports[i] = convert_task_name_to_port(task);
				break;
		}
	}

	kfree(tasks, capacity * sizeof(*tasks));

	*task_list = (task_array_t)ports;
	*count = used;
	return KERN_SUCCESS;
};

kern_return_t processor_set_tasks(processor_set_t pset, task_array_t* task_list, mach_msg_type_number_t* count) {
	return processor_set_tasks_internal(pset, task_list, count, TASK_FLAVOR_CONTROL);
};

kern_return_t processor_set_tasks_with_flavor(processor_set_t pset, mach_task_flavor_t flavor, task_array_t* task_list, mach_msg_type_number_t* count) {
	return processor_set_tasks_internal(pset, task_list, count, flavor);
};

kern_return_t processor_set_threads(processor_set_t pset, thread_array_t* thread_list, mach_msg_type_number_t* count) {
	// guest-reachable through MIG.
	// XNU release kernels answer this one KERN_FAILURE (DEVELOPMENT/DEBUG only).
	return KERN_FAILURE;
};

kern_return_t processor_start_from_user(processor_t processor) {
	// guest-reachable through MIG.
	// Linux CPUs are not brought online from a container.
	if (processor == PROCESSOR_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_NOT_SUPPORTED;
};

// <copied from="xnu://7195.141.2/osfmk/kern/processor.c" modified>

kern_return_t
processor_set_info(
	processor_set_t         pset,
	int                     flavor,
	host_t                  *host,
	processor_set_info_t    info,
	mach_msg_type_number_t  *count)
{
	if (pset == PROCESSOR_SET_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flavor == PROCESSOR_SET_BASIC_INFO) {
		processor_set_basic_info_t      basic_info;

		if (*count < PROCESSOR_SET_BASIC_INFO_COUNT) {
			return KERN_FAILURE;
		}

		basic_info = (processor_set_basic_info_t) info;
#ifdef __DARLING__
		basic_info->processor_count = get_nprocs();
#else
#if defined(__x86_64__)
		basic_info->processor_count = processor_avail_count_user;
#else
		basic_info->processor_count = processor_avail_count;
#endif
#endif
		basic_info->default_policy = POLICY_TIMESHARE;

		*count = PROCESSOR_SET_BASIC_INFO_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_TIMESHARE_DEFAULT) {
		policy_timeshare_base_t ts_base;

		if (*count < POLICY_TIMESHARE_BASE_COUNT) {
			return KERN_FAILURE;
		}

		ts_base = (policy_timeshare_base_t) info;
		ts_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_TIMESHARE_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_FIFO_DEFAULT) {
		policy_fifo_base_t              fifo_base;

		if (*count < POLICY_FIFO_BASE_COUNT) {
			return KERN_FAILURE;
		}

		fifo_base = (policy_fifo_base_t) info;
		fifo_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_FIFO_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_RR_DEFAULT) {
		policy_rr_base_t                rr_base;

		if (*count < POLICY_RR_BASE_COUNT) {
			return KERN_FAILURE;
		}

		rr_base = (policy_rr_base_t) info;
		rr_base->base_priority = BASEPRI_DEFAULT;
		rr_base->quantum = 1;

		*count = POLICY_RR_BASE_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_TIMESHARE_LIMITS) {
		policy_timeshare_limit_t        ts_limit;

		if (*count < POLICY_TIMESHARE_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		ts_limit = (policy_timeshare_limit_t) info;
		ts_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_TIMESHARE_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_FIFO_LIMITS) {
		policy_fifo_limit_t             fifo_limit;

		if (*count < POLICY_FIFO_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		fifo_limit = (policy_fifo_limit_t) info;
		fifo_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_FIFO_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_RR_LIMITS) {
		policy_rr_limit_t               rr_limit;

		if (*count < POLICY_RR_LIMIT_COUNT) {
			return KERN_FAILURE;
		}

		rr_limit = (policy_rr_limit_t) info;
		rr_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_RR_LIMIT_COUNT;
		*host = &realhost;
		return KERN_SUCCESS;
	} else if (flavor == PROCESSOR_SET_ENABLED_POLICIES) {
		int                             *enabled;

		if (*count < (sizeof(*enabled) / sizeof(int))) {
			return KERN_FAILURE;
		}

		enabled = (int *) info;
		*enabled = POLICY_TIMESHARE | POLICY_RR | POLICY_FIFO;

		*count = sizeof(*enabled) / sizeof(int);
		*host = &realhost;
		return KERN_SUCCESS;
	}


	*host = HOST_NULL;
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
processor_info_count(
	processor_flavor_t              flavor,
	mach_msg_type_number_t  *count)
{
	switch (flavor) {
	case PROCESSOR_BASIC_INFO:
		*count = PROCESSOR_BASIC_INFO_COUNT;
		break;

	case PROCESSOR_CPU_LOAD_INFO:
		*count = PROCESSOR_CPU_LOAD_INFO_COUNT;
		break;

	default:
		return cpu_info_count(flavor, count);
	}

	return KERN_SUCCESS;
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/i386/cpu.c">

/*ARGSUSED*/
kern_return_t
cpu_info_count(
	__unused processor_flavor_t      flavor,
	unsigned int                    *count)
{
	*count = 0;
	return KERN_FAILURE;
}

// </copied>
