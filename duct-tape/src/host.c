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

// Linux file access
int open(const char* path, int flags, ...);
long read(int fd, void* buffer, unsigned long count);
int close(int fd);
#define LINUX_O_RDONLY 0
#define LINUX_O_CLOEXEC 02000000

// reads the first CPU number from cpu<N>/topology/thread_siblings_list.
// returns false if the CPU has no topology information (e.g. it's offline).
static bool first_thread_sibling(unsigned long cpu, unsigned long* first) {
	static const char prefix[] = "/sys/devices/system/cpu/cpu";
	static const char suffix[] = "/topology/thread_siblings_list";
	char path[sizeof(prefix) + 20 + sizeof(suffix)];
	char digits[20];
	size_t digit_count = 0;
	size_t length = 0;
	char buffer[32];
	long result;
	int fd;

	do {
		digits[digit_count++] = '0' + (cpu % 10);
		cpu /= 10;
	} while (cpu != 0);

	memcpy(path, prefix, sizeof(prefix) - 1);
	length = sizeof(prefix) - 1;
	while (digit_count > 0) {
		path[length++] = digits[--digit_count];
	}
	memcpy(&path[length], suffix, sizeof(suffix));

	fd = open(path, LINUX_O_RDONLY | LINUX_O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	result = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);

	if (result <= 0 || buffer[0] < '0' || buffer[0] > '9') {
		return false;
	}
	buffer[result] = '\0';

	*first = 0;
	for (const char* ptr = buffer; *ptr >= '0' && *ptr <= '9'; ++ptr) {
		*first = (*first * 10) + (*ptr - '0');
	}
	return true;
};

// counts the physical cores that have at least one online CPU.
// returns 0 if the topology can't be determined.
static uint32_t count_online_cores(uint32_t max_cpus) {
	uint32_t cores = 0;

	for (uint32_t cpu = 0; cpu < max_cpus; ++cpu) {
		unsigned long first;

		if (!first_thread_sibling(cpu, &first)) {
			continue;
		}

		// the sibling list only contains online CPUs, so each core with an online
		// CPU has exactly one CPU that is the first entry in its own sibling list
		if (first == cpu) {
			++cores;
		}
	}

	return cores;
};

static void cache_core_count(void* context) {
	uint32_t* cached_core_count = context;
	*cached_core_count = count_online_cores(sysconf(_SC_NPROCESSORS_CONF));
};

static void cache_sysinfo(void* context) {
	struct sysinfo* cached_sysinfo = context;

	if (sysinfo(cached_sysinfo) < 0) {
		panic("Failed to retrieve sysinfo");
	}
};

// the configured memory size (`MemorySize` in the platform identity), or 0 for the host's
static uint64_t configured_memory_size = 0;

void dtape_host_set_memory_size(uint64_t memory_size) {
	__atomic_store_n(&configured_memory_size, memory_size, __ATOMIC_RELAXED);
};

kern_return_t host_info(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t* count) {
	static libsimple_once_t once_token = LIBSIMPLE_ONCE_INITIALIZER;
	static struct sysinfo cached_sysinfo;
	static libsimple_once_t core_count_once_token = LIBSIMPLE_ONCE_INITIALIZER;
	static uint32_t cached_core_count;

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

			uint64_t memsize = __atomic_load_n(&configured_memory_size, __ATOMIC_RELAXED);
			if (memsize == 0) {
				memsize = cached_sysinfo.totalram * cached_sysinfo.mem_unit;
			}

			basic_info->memory_size = memsize;
#if __x86_64__ || __i386__
			basic_info->cpu_type = CPU_TYPE_X86;
#if __x86_64__
			basic_info->cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
#else
			basic_info->cpu_subtype = CPU_SUBTYPE_I386_ALL;
#endif
#elif __aarch64__
			basic_info->cpu_type = CPU_TYPE_ARM64;
			basic_info->cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
#else
			#error Unknown CPU type
#endif
			basic_info->max_cpus = sysconf(_SC_NPROCESSORS_CONF);
			basic_info->avail_cpus = sysconf(_SC_NPROCESSORS_ONLN);

			// if there's room for the modern structure, fill in some additional info
			if (*count >= HOST_BASIC_INFO_COUNT) {
				libsimple_once(&core_count_once_token, cache_core_count, &cached_core_count);

				basic_info->cpu_threadtype = CPU_THREADTYPE_NONE;

				if (cached_core_count != 0 && cached_core_count <= basic_info->avail_cpus) {
					basic_info->physical_cpu = cached_core_count;
					// offline CPUs have no topology information; assume they have
					// the same number of threads per core as the online ones
					basic_info->physical_cpu_max = (uint32_t)(((uint64_t)basic_info->max_cpus * cached_core_count) / basic_info->avail_cpus);
					if (basic_info->physical_cpu_max < basic_info->physical_cpu) {
						basic_info->physical_cpu_max = basic_info->physical_cpu;
					}
				} else {
					basic_info->physical_cpu = basic_info->avail_cpus;
					basic_info->physical_cpu_max = basic_info->max_cpus;
				}

				basic_info->logical_cpu = basic_info->avail_cpus;
				basic_info->logical_cpu_max = basic_info->max_cpus;

				basic_info->max_mem = memsize;

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

		case HOST_PREFERRED_USER_ARCH: {
			host_preferred_user_arch_t user_arch_info;

			if (*count < HOST_PREFERRED_USER_ARCH_COUNT) {
				return KERN_FAILURE;
			}

			*count = HOST_PREFERRED_USER_ARCH_COUNT;

			user_arch_info = (void*)info;

#if __x86_64__ || __i386__
			user_arch_info->cpu_type = CPU_TYPE_X86;
#if __x86_64__
			user_arch_info->cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
#else
			user_arch_info->cpu_subtype = CPU_SUBTYPE_I386_ALL;
#endif
#elif __aarch64__
			// TODO: check whether this is actually what ARM64 macOS returns
			user_arch_info->cpu_type = CPU_TYPE_ARM64;
			user_arch_info->cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
#else
			#error HOST_PREFERRED_USER_ARCH not implemented for this architecture
#endif

			return KERN_SUCCESS;
		};

		case HOST_SCHED_INFO:
			dtape_stub_unsafe("HOST_SCHED_INFO");
		case HOST_RESOURCE_SIZES:
			dtape_stub_unsafe("HOST_RESOURCE_SIZES");
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
	switch (flavor) {
		// we can get away with not implementing it
		case HOST_VM_INFO: {
			vm_statistics_t stat32 = (vm_statistics_t)info;

			if (*count < HOST_VM_INFO_REV0_COUNT) {
				return KERN_FAILURE;
			}

			dtape_stub_safe("HOST_VM_INFO");
			memset(stat32, 0, (*count) * sizeof(integer_t));

			return KERN_SUCCESS;
		}

		case HOST_CPU_LOAD_INFO:
			dtape_stub_safe("HOST_CPU_LOAD_INFO");
			return KERN_INVALID_ARGUMENT;

		default:
			dtape_stub_unsafe();
	}
};

kern_return_t vm_stats(void* info, unsigned int* count) {
	vm_statistics64_t stat = (vm_statistics64_t)info;

	if (*count < HOST_VM_INFO64_COUNT)
		return (KERN_FAILURE);

	memset(stat, 0, sizeof(*stat));

	dtape_stub("TODO: actually fill in the values with something useful");

	*count = HOST_VM_INFO64_COUNT;

	return KERN_SUCCESS;
};
