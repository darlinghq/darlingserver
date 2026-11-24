// Feeds the signal number, si_code and address of each kind of Linux fault to the real
// dtape_thread_process_signal(), cut out of duct-tape/src/thread.c by tests/host/exception-codes-inc.sh,
// captures the exception it raises, and checks it and the BSD signal that the real ux_exception() makes of it
// when no handler takes the exception.
#define __DARLING__ 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef int64_t mach_exception_data_type_t;
typedef int64_t mach_exception_code_t;
typedef int64_t mach_exception_subcode_t;
typedef int mach_msg_type_number_t;
typedef int exception_type_t;

typedef struct thread { int unused; } *thread_t;
typedef struct dtape_thread {
	bool processing_signal;
	void* context;
	struct thread xnu_thread;
	int suspension_mutex, suspension_condvar;
} dtape_thread_t;
#define dtape_mutex_lock(mutex) ((void)(mutex))
#define dtape_mutex_unlock(mutex) ((void)(mutex))
#define dtape_condvar_signal(condvar, count) ((void)(condvar), (void)(count))
typedef struct dtape_task { bool has_sigexc; } dtape_task_t;

static dtape_task_t task;
static dtape_task_t* dtape_task_for_thread(dtape_thread_t* thread) { (void)thread; return &task; }

static int raised, raised_exception;
static mach_exception_data_type_t raised_codes[2];

static void exception_triage_thread(exception_type_t exception, mach_exception_data_type_t* codes,
		mach_msg_type_number_t count, thread_t thread) {
	(void)thread;
	raised++;
	raised_exception = exception;
	raised_codes[0] = codes[0];
	raised_codes[1] = count > 1 ? codes[1] : 0;
}

static void bsd_exception(exception_type_t exception, mach_exception_data_type_t* codes, mach_msg_type_number_t count) {
	exception_triage_thread(exception, codes, count, NULL);
}

static int pending_signal;
static void set_pending_signal(void* context, int signal) { (void)context; pending_signal = signal; }
static const struct { void (*thread_set_pending_signal)(void*, int); } hooks = { set_pending_signal };
static const typeof(hooks)* dtape_hooks = &hooks;

#define dtape_log_debug(...) ((void)0)
#define dtape_stub(...) ((void)0)

#include EXCEPTION_CODES_INC

#if defined(__aarch64__)
#define ALIGN_CODE EXC_ARM_DA_ALIGN
#else
#define ALIGN_CODE EXC_I386_ALIGNFLT
#endif

// the si_code values of Linux faults (asm-generic/siginfo.h)
enum { SEGV_MAPERR_ = 1, SEGV_ACCERR_ = 2, SEGV_PKUERR_ = 4, BUS_ADRALN_ = 1, BUS_ADRERR_ = 2, BUS_OBJERR_ = 3 };

static int failures;

static void check(const char* what, int linux_signal, int si_code, uintptr_t address,
		int exception, mach_exception_data_type_t code, mach_exception_data_type_t subcode, int bsd_signal) {
	dtape_thread_t thread = {0};
	raised = 0;
	dtape_thread_process_signal(&thread, 0, linux_signal, si_code, address);
	int signal = raised ? ux_exception(raised_exception, raised_codes[0], raised_codes[1]) : 0;
	if (raised != 1 || raised_exception != exception || raised_codes[0] != code || raised_codes[1] != subcode
			|| signal != bsd_signal) {
		printf("FAIL: %s: got exception %d, code %#llx, subcode %#llx, signal %d; "
				"expected exception %d, code %#llx, subcode %#llx, signal %d\n", what,
				raised_exception, (long long)raised_codes[0], (long long)raised_codes[1], signal,
				exception, (long long)code, (long long)subcode, bsd_signal);
		failures++;
	}
}

int main(void) {
	const uintptr_t a = 0x7f0012345000;

	// observed on macOS 27 (x86_64 under Rosetta, and arm64) with a thread exception port and a
	// sigaction handler: unmapped page, PROT_NONE page or write to a read-only page, file mapping past EOF
	check("unmapped page", LINUX_SIGSEGV, SEGV_MAPERR_, a, EXC_BAD_ACCESS, KERN_INVALID_ADDRESS, a, SIGSEGV);
	check("page without access", LINUX_SIGSEGV, SEGV_ACCERR_, a, EXC_BAD_ACCESS, KERN_PROTECTION_FAILURE, a, SIGBUS);
	check("file mapping past EOF", LINUX_SIGBUS, BUS_ADRERR_, a, EXC_BAD_ACCESS, KERN_MEMORY_ERROR, a, SIGBUS);

	// by analogy: a protection key denies access like page protection, and an object error is a failure of the
	// memory object like a read past EOF
	check("protection key", LINUX_SIGSEGV, SEGV_PKUERR_, a, EXC_BAD_ACCESS, KERN_PROTECTION_FAILURE, a, SIGBUS);
	check("object error", LINUX_SIGBUS, BUS_OBJERR_, a, EXC_BAD_ACCESS, KERN_MEMORY_ERROR, a, SIGBUS);

	// unchanged: general protection faults (no address) and alignment faults
	check("general protection", LINUX_SIGSEGV, LINUX_SI_KERNEL, 0, EXC_BAD_ACCESS, KERN_INVALID_ADDRESS, 0, SIGSEGV);
	check("alignment", LINUX_SIGBUS, BUS_ADRALN_, a, EXC_BAD_ACCESS, ALIGN_CODE, 0, SIGBUS);

	if (failures == 0)
		printf("PASS exception codes\n");
	return failures != 0;
}
