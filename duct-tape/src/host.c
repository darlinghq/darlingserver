#include <darlingserver/duct-tape/stubs.h>

#include <kern/host.h>
#include <mach_debug/mach_debug.h>

#include <libsimple/lock.h>

// Linux sysinfo (from the sysinfo man page)
struct sysinfo {
	long uptime;
	unsigned long loads[3];
	unsigned long totalram;
	unsigned long freeram;
	unsigned long sharedram;
	unsigned long bufferram;
	unsigned long totalswap;
	unsigned long freeswap;
	unsigned short procs;
	unsigned long totalhigh;
	unsigned long freehigh;
	unsigned int mem_unit;
	char _f[20 - 2 * sizeof(long) - sizeof(int)];
};
int sysinfo(struct sysinfo *info);

// Linux sysconf
long sysconf(int name);
#define _SC_NPROCESSORS_CONF 83
#define _SC_NPROCESSORS_ONLN 84

static void cache_sysinfo(void* context) {
	struct sysinfo* cached_sysinfo = context;

	if (sysinfo(cached_sysinfo) < 0) {
		panic("Failed to retrieve sysinfo");
	}
};

kern_return_t host_info(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t* count) {
	static libsimple_once_t once_token = LIBSIMPLE_ONCE_INITIALIZER;
	static struct sysinfo cached_sysinfo;

	if (host == HOST_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
		case HOST_BASIC_INFO: {
			host_basic_info_t basic_info = (host_basic_info_t)info;

			// need at least enough space for the legacy structure
			if (*count < HOST_BASIC_INFO_OLD_COUNT) {
				return KERN_FAILURE;
			}

			libsimple_once(&once_token, cache_sysinfo, &cached_sysinfo);

			basic_info->memory_size = cached_sysinfo.totalram;
#if __x86_64__ || __i386__
			basic_info->cpu_type = CPU_TYPE_X86;
			basic_info->cpu_subtype = CPU_SUBTYPE_X86_ARCH1;
#else
			#error Unknown CPU type
#endif
			basic_info->max_cpus = sysconf(_SC_NPROCESSORS_CONF);
			basic_info->avail_cpus = sysconf(_SC_NPROCESSORS_ONLN);

			// if there's room for the modern structure, fill in some additional info
			if (*count >= HOST_BASIC_INFO_COUNT) {
				// TODO: properly differentiate physical vs. logical cores
				dtape_stub_safe("modern HOST_BASIC_INFO");
				basic_info->cpu_threadtype = CPU_THREADTYPE_NONE;
				basic_info->physical_cpu = basic_info->avail_cpus;
				basic_info->physical_cpu_max = basic_info->max_cpus;
				basic_info->logical_cpu = basic_info->avail_cpus;
				basic_info->logical_cpu_max = basic_info->max_cpus;

				basic_info->max_mem = basic_info->memory_size;

				*count = HOST_BASIC_INFO_COUNT;
			} else {
				*count = HOST_BASIC_INFO_OLD_COUNT;
			}

			return KERN_SUCCESS;
		}

		case HOST_PRIORITY_INFO: {
			// <copied from="xnu://7195.141.2/osfmk/kern/host.c">
			host_priority_info_t priority_info;

			if (*count < HOST_PRIORITY_INFO_COUNT) {
				return KERN_FAILURE;
			}

			priority_info = (host_priority_info_t)info;

			priority_info->kernel_priority = MINPRI_KERNEL;
			priority_info->system_priority = MINPRI_KERNEL;
			priority_info->server_priority = MINPRI_RESERVED;
			priority_info->user_priority = BASEPRI_DEFAULT;
			priority_info->depress_priority = DEPRESSPRI;
			priority_info->idle_priority = IDLEPRI;
			priority_info->minimum_priority = MINPRI_USER;
			priority_info->maximum_priority = MAXPRI_RESERVED;

			*count = HOST_PRIORITY_INFO_COUNT;

			return KERN_SUCCESS;
			// </copied>
		}

		case HOST_DEBUG_INFO_INTERNAL:
			return KERN_NOT_SUPPORTED;

		case HOST_SCHED_INFO:
			dtape_stub_unsafe("HOST_SCHED_INFO");
		case HOST_RESOURCE_SIZES:
			dtape_stub_unsafe("HOST_RESOURCE_SIZES");
		case HOST_PREFERRED_USER_ARCH:
			dtape_stub_unsafe("HOST_PREFERRED_USER_ARCH");
		case HOST_CAN_HAS_DEBUGGER:
			dtape_stub_unsafe("HOST_CAN_HAS_DEBUGGER");
		case HOST_VM_PURGABLE:
			dtape_stub_unsafe("HOST_VM_PURGABLE");

		case HOST_MACH_MSG_TRAP:
		case HOST_SEMAPHORE_TRAPS:
			*count = 0;
			return KERN_SUCCESS;

		default:
			return KERN_INVALID_ARGUMENT;
	}
};

kern_return_t host_default_memory_manager(host_priv_t host_priv, memory_object_default_t* default_manager, memory_object_cluster_size_t cluster_size) {
	dtape_stub_unsafe();
};

kern_return_t host_get_boot_info(host_priv_t host_priv, kernel_boot_info_t boot_info) {
	dtape_stub_unsafe();
};

kern_return_t host_get_UNDServer(host_priv_t host_priv, UNDServerRef* serverp) {
	dtape_stub_unsafe();
};

kern_return_t host_set_UNDServer(host_priv_t host_priv, UNDServerRef server) {
	dtape_stub_unsafe();
};

kern_return_t host_lockgroup_info(host_t host, lockgroup_info_array_t* lockgroup_infop, mach_msg_type_number_t* lockgroup_infoCntp) {
	dtape_stub_unsafe();
};

kern_return_t host_reboot(host_priv_t host_priv, int options) {
	dtape_stub_unsafe();
};

kern_return_t host_security_create_task_token(host_security_t host_security, task_t parent_task, security_token_t sec_token, audit_token_t audit_token, host_priv_t host_priv, ledger_port_array_t ledger_ports, mach_msg_type_number_t num_ledger_ports, boolean_t inherit_memory, task_t* child_task) {
	dtape_stub_safe();
	return KERN_NOT_SUPPORTED;
};

kern_return_t host_security_set_task_token(host_security_t host_security, task_t task, security_token_t sec_token, audit_token_t audit_token, host_priv_t host_priv) {
	dtape_stub_unsafe();
};

kern_return_t host_virtual_physical_table_info(host_t host, hash_info_bucket_array_t* infop, mach_msg_type_number_t* countp) {
	dtape_stub_unsafe();
};

kern_return_t host_statistics(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t vm_stats(void* info, unsigned int* count) {
	dtape_stub_unsafe();
};
