#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/thread.h>
#include <kern/policy_internal.h>

#include <sys/file_internal.h>
#include <pthread/workqueue_internal.h>

unsigned int kdebug_enable = 0;

#undef panic

__attribute__((noreturn))
void abort(void);

typedef struct FILE FILE;
extern FILE* stdout;

int fflush(FILE* stream);

#ifndef DTAPE_FATAL_STUBS
	#define DTAPE_FATAL_STUBS 0
#endif

void dtape_stub_log(const char* function_name, int safety) {
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

	dtape_log(log_level, "stub%s: %s", kind_info, function_name);

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
