#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/thread.h>
#include <kern/policy_internal.h>

#include <sys/file_internal.h>
#include <pthread/workqueue_internal.h>

#include <kern/host.h>
#include <mach_debug/lockgroup_info.h>

unsigned int kdebug_enable = 0;
uint32_t avenrun[3] = {0};
uint32_t mach_factor[3] = {0};
vm_object_t compressor_object;
uint32_t c_segment_pages_compressed;
expired_task_statistics_t dead_task_statistics;
struct machine_info machine_info;
int sched_allow_NO_SMT_threads;

#undef panic

__attribute__((noreturn))
void abort(void);

typedef struct FILE FILE;
extern FILE* stdout;

int fflush(FILE* stream);

#ifndef DTAPE_FATAL_STUBS
	#define DTAPE_FATAL_STUBS 0
#endif

void dtape_stub_log(const char* function_name, int safety, const char* subsection) {
	dtape_log_level_t log_level;
	bool do_abort;
	const char* kind_info;

	if (safety == 0) {
		log_level = dtape_log_level_warning;
#if DTAPE_FATAL_STUBS
		do_abort = true;
#else
		do_abort = false;
#endif
		kind_info = "";
	} else if (safety < 0) {
		log_level = dtape_log_level_error;
		do_abort = true;
		kind_info = " (unsafe)";
	} else {
		log_level = dtape_log_level_debug;
		do_abort = false;
		kind_info = " (safe)";
	}

	dtape_log(log_level, "stub%s: %s%s%s", kind_info, function_name, subsection[0] == '\0' ? "" : ":", subsection);

	if (do_abort) {
		abort();
	}
};

void panic(const char* message, ...) {
	va_list args;
	va_start(args, message);
	printf("darlingserver duct-tape panic: ");
	vprintf(message, args);
	va_end(args);
	printf("\n");
	fflush(stdout);
	abort();
};

kern_return_t bank_get_bank_ledger_thread_group_and_persona(ipc_voucher_t voucher, ledger_t* bankledger, struct thread_group** banktg, uint32_t* persona_id) {
	dtape_stub();
	return KERN_FAILURE;
};

int cpu_number(void) {
	dtape_stub_safe();
	return 0;
};

void fileport_releasefg(struct fileglob* fg) {
	dtape_stub();
};

void workq_deallocate_safe(struct workqueue* wq) {
	dtape_stub();
};

bool workq_is_current_thread_updating_turnstile(struct workqueue* wq) {
	dtape_stub();
	return false;
};

void workq_reference(struct workqueue* wq) {
	dtape_stub();
};

void workq_schedule_creator_turnstile_redrive(struct workqueue* wq, bool locked) {
	dtape_stub();
};

kern_return_t uext_server(ipc_kmsg_t request, ipc_kmsg_t* reply) {
	dtape_stub();
	return KERN_FAILURE;
};

void upl_no_senders(ipc_port_t port, mach_port_mscount_t mscount) {
	dtape_stub_safe();
};

void suid_cred_destroy(ipc_port_t port) {
	dtape_stub();
};

void suid_cred_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

boolean_t ml_get_interrupts_enabled(void) {
	return TRUE;
};

boolean_t ml_set_interrupts_enabled(boolean_t enable) {
	return TRUE;
};

boolean_t ml_delay_should_spin(uint64_t interval) {
	return FALSE;
};

unsigned int ml_wait_max_cpus(void) {
	return 0;
};

void mach_destroy_memory_entry(ipc_port_t port) {
	dtape_stub();
};

void klist_init(struct klist* list) {
	dtape_stub();
};

void knote(struct klist* list, long hint) {
	dtape_stub();
};

void knote_vanish(struct klist* list, bool make_active) {
	dtape_stub();
};

struct turnstile* kqueue_turnstile(struct kqueue* kqu) {
	dtape_stub();
	return NULL;
};

void waitq_set__CALLING_PREPOST_HOOK__(waitq_set_prepost_hook_t* kq_hook) {
	dtape_stub();
};

void work_interval_port_notify(mach_msg_header_t* msg) {
	dtape_stub();
};

int proc_get_effective_thread_policy(thread_t thread, int flavor) {
	dtape_stub();
	return -1;
};

boolean_t PE_parse_boot_argn(const char* arg_string, void* arg_ptr, int max_len) {
	dtape_stub_safe();
	return FALSE;
};

boolean_t machine_timeout_suspended(void) {
	dtape_stub_safe();
	return true;
};

boolean_t IOTaskHasEntitlement(task_t task, const char* entitlement) {
	dtape_stub_safe();
	return TRUE;
};

kern_return_t kmod_create(host_priv_t host_priv, vm_address_t addr, kmod_t* id) {
	dtape_stub_safe();
	return KERN_NOT_SUPPORTED;
};

kern_return_t kmod_destroy(host_priv_t host_priv, kmod_t id) {
	dtape_stub_safe();
	return KERN_NOT_SUPPORTED;
};

kern_return_t kmod_control(host_priv_t host_priv, kmod_t id, kmod_control_flavor_t flavor, kmod_args_t* data, mach_msg_type_number_t* dataCount) {
	dtape_stub_safe();
	return KERN_NOT_SUPPORTED;
};

kern_return_t kmod_get_info(host_t host, kmod_info_array_t* kmod_list, mach_msg_type_number_t* kmodCount) {
	dtape_stub_safe();
	return KERN_NOT_SUPPORTED;
};

kern_return_t kext_request(host_priv_t hostPriv, uint32_t clientLogSpec, vm_offset_t requestIn, mach_msg_type_number_t requestLengthIn, vm_offset_t* responseOut, mach_msg_type_number_t* responseLengthOut, vm_offset_t* logDataOut, mach_msg_type_number_t* logDataLengthOut, kern_return_t* op_result) {
	dtape_stub_unsafe();
};

uint32_t PE_i_can_has_debugger(uint32_t* something) {
	dtape_stub_unsafe();
};

bool work_interval_port_type_render_server(mach_port_name_t port_name) {
	dtape_stub_safe();
	return false;
};

ipc_port_t convert_suid_cred_to_port(suid_cred_t sc) {
	dtape_stub_unsafe();
};

kern_return_t handle_ux_exception(thread_t thread, int exception, mach_exception_code_t code, mach_exception_subcode_t subcode) {
	dtape_stub_unsafe();
};
