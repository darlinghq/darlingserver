/* kernelrpc_stubs.c — FreeBSD port: thin wrappers / stubs for XNU kernel-trap
 * entry points referenced by MIG-generated server stubs but not implemented in
 * the duct-tape src/  set.  Real semantics can be wired up incrementally. */

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/locks.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>
#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/thread_policy.h>

/* ── Forward declarations for dtape memory.c functions ──────────────────── */
/* Parameter names omitted to avoid collisions with function-like macros
 * (e.g. mask() in kern/bits.h, copy() in some headers). */
extern kern_return_t mach_vm_allocate_kernel(vm_map_t, mach_vm_offset_t *,
    mach_vm_size_t, int, vm_tag_t);
extern kern_return_t vm_deallocate(vm_map_t, vm_offset_t, vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_offset_t,
    mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_map_external(vm_map_t, mach_vm_offset_t *,
    mach_vm_size_t, mach_vm_offset_t, int, ipc_port_t,
    vm_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_remap_external(vm_map_t, mach_vm_offset_t *,
    mach_vm_size_t, mach_vm_offset_t, int, vm_map_t, mach_vm_offset_t,
    boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);
extern kern_return_t mach_vm_remap_new_external(vm_map_t, mach_vm_offset_t *,
    mach_vm_size_t, mach_vm_offset_t, int, mach_port_t, mach_vm_offset_t,
    boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);
extern kern_return_t mach_vm_purgable_control(vm_map_t, mach_vm_offset_t,
    vm_purgable_t, int *);
extern kern_return_t mach_vm_read(vm_map_t, mach_vm_address_t,
    mach_vm_size_t, pointer_t *, mach_msg_type_number_t *);
/* current_task() is a macro expanding to current_task_fast() in kern/task.h */

/* ── mach_vm trap wrappers ───────────────────────────────────────────────── */

kern_return_t _kernelrpc_mach_vm_allocate_external(task_t task,
    mach_vm_address_t *addr, mach_vm_size_t size, int flags)
{
    return mach_vm_allocate_kernel(task->map, (mach_vm_offset_t *)addr,
        size, flags, 0 /* VM_KERN_MEMORY_NONE */);
}

kern_return_t _kernelrpc_mach_vm_deallocate(task_t task,
    mach_vm_address_t start, mach_vm_size_t size)
{
    return vm_deallocate(task->map, (vm_offset_t)start, (vm_size_t)size);
}

kern_return_t _kernelrpc_mach_vm_protect(task_t task,
    mach_vm_address_t address, mach_vm_size_t size,
    boolean_t set_maximum, vm_prot_t new_protection)
{
    return mach_vm_protect(task->map, address, size, set_maximum, new_protection);
}

kern_return_t _kernelrpc_mach_vm_map_external(task_t task,
    mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask,
    int flags, ipc_port_t port, vm_object_offset_t offset, boolean_t copy,
    vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance)
{
    return mach_vm_map_external(task->map, (mach_vm_offset_t *)address, size,
        mask, flags, port, offset, copy, cur_protection, max_protection,
        inheritance);
}

kern_return_t _kernelrpc_mach_vm_remap_external(task_t target_task,
    mach_vm_address_t *target_address, mach_vm_size_t size,
    mach_vm_offset_t mask, int flags, task_t src_task,
    mach_vm_address_t src_address, boolean_t copy,
    vm_prot_t *cur_protection, vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
    return mach_vm_remap_external(target_task->map,
        (mach_vm_offset_t *)target_address, size, mask, flags,
        src_task->map, src_address, copy, cur_protection, max_protection,
        inheritance);
}

kern_return_t _kernelrpc_mach_vm_remap_new_external(task_t target_task,
    mach_vm_address_t *target_address, mach_vm_size_t size,
    mach_vm_offset_t mask, int flags, mach_port_t src_tport,
    mach_vm_address_t memory_address, boolean_t copy,
    vm_prot_t *cur_protection, vm_prot_t *max_protection,
    vm_inherit_t inheritance)
{
    return mach_vm_remap_new_external(target_task->map,
        (mach_vm_offset_t *)target_address, size, mask, flags,
        src_tport, memory_address, copy, cur_protection, max_protection,
        inheritance);
}

kern_return_t _kernelrpc_mach_vm_purgable_control(task_t task,
    mach_vm_address_t address, vm_purgable_t control, int *state)
{
    return mach_vm_purgable_control(task->map, address, control, state);
}

kern_return_t _kernelrpc_mach_vm_read(task_t task,
    mach_vm_address_t addr, mach_vm_size_t size,
    vm_offset_t *data, mach_msg_type_number_t *data_size)
{
    return mach_vm_read(task->map, addr, size, (pointer_t *)data, data_size);
}

/* ── host page size ─────────────────────────────────────────────────────── */

kern_return_t _host_page_size(host_t host, vm_size_t *out_page_size)
{
    (void)host;
    *out_page_size = PAGE_SIZE;
    return KERN_SUCCESS;
}

/* ── task identity ──────────────────────────────────────────────────────── */

kern_return_t _kernelrpc_mach_task_is_self(task_t task, boolean_t *is_self)
{
    *is_self = (task == current_task()) ? TRUE : FALSE;
    return KERN_SUCCESS;
}

/* ── voucher stubs ──────────────────────────────────────────────────────── */

kern_return_t _kernelrpc_host_create_mach_voucher(host_t host,
    mach_voucher_attr_raw_recipe_array_t recipes,
    mach_voucher_attr_raw_recipe_size_t recipesCnt,
    ipc_voucher_t *voucher)
{
    (void)host; (void)recipes; (void)recipesCnt;
    *voucher = IPC_VOUCHER_NULL;
    return KERN_NOT_SUPPORTED;
}

kern_return_t _kernelrpc_mach_voucher_extract_attr_recipe(ipc_voucher_t voucher,
    mach_voucher_attr_key_t key,
    mach_voucher_attr_raw_recipe_t recipe,
    mach_voucher_attr_raw_recipe_size_t *recipe_size)
{
    (void)voucher; (void)key; (void)recipe;
    *recipe_size = 0;
    return KERN_NOT_SUPPORTED;
}

/* ── thread policy stubs ────────────────────────────────────────────────── */

kern_return_t _kernelrpc_thread_policy(thread_t thread, policy_t policy,
    policy_base_t base, mach_msg_type_number_t baseCnt, boolean_t set_limit)
{
    (void)thread; (void)policy; (void)base; (void)baseCnt; (void)set_limit;
    return KERN_NOT_SUPPORTED;
}

kern_return_t _kernelrpc_thread_policy_set(thread_t thread,
    thread_policy_flavor_t flavor,
    thread_policy_t policy_info,
    mach_msg_type_number_t policy_infoCnt)
{
    (void)thread; (void)flavor; (void)policy_info; (void)policy_infoCnt;
    return KERN_NOT_SUPPORTED;
}

kern_return_t _kernelrpc_thread_set_policy(thread_t thread,
    processor_set_t pset, policy_t policy,
    policy_base_t base, mach_msg_type_number_t baseCnt,
    policy_limit_t limit, mach_msg_type_number_t limitCnt)
{
    (void)thread; (void)pset; (void)policy;
    (void)base; (void)baseCnt; (void)limit; (void)limitCnt;
    return KERN_NOT_SUPPORTED;
}

/* ── KDP / lock debug stubs ─────────────────────────────────────────────── */

unsigned int not_in_kdp = 1; /* always "not in kdp" on FreeBSD */

boolean_t kdp_lck_spin_is_acquired(lck_spin_t *lck)
{
    (void)lck;
    return FALSE;
}

/* ── Timer stubs ─────────────────────────────────────────────────────────── */

void ml_timer_evaluate(void) {}

void timer_call_cpu(int cpu, void (*fn)(void *), void *arg)
{
    (void)cpu;
    if (fn) fn(arg);
}

void timer_resync_deadlines(void) {}

/* ── percpu_base (single-CPU: no secondary CPUs) ────────────────────────── */
/* percpu_slot_* and section$start/end$__DATA$__percpu are in freebsd_percpu.s */

#include <kern/percpu.h>
struct percpu_base percpu_base = {
    .start = (vm_offset_t)-1,   /* no secondary CPUs: start > end */
    .end   = 0,
};

/* ── Scheduler stubs ─────────────────────────────────────────────────────── */

/* sched_stats_active: declared as 'bool' in kern/sched_prim.h */
bool sched_stats_active = false;

void sched_timebase_init(void) {}

/* sched_dualq_dispatch: zero-initialized dispatch table (all fn ptrs NULL).
 * Any SCHED(f) call will crash; acceptable until scheduler is wired up. */
#include <kern/sched_prim.h>
const struct sched_dispatch_table sched_dualq_dispatch = {
    .sched_name = "dtape-stub",
};

/* ── Clock / commpage stubs ─────────────────────────────────────────────── */

void commpage_set_timestamp(uint64_t abstime, uint64_t secs,
    uint64_t frac, uint64_t scale, uint64_t tick_per_sec)
{
    (void)abstime; (void)secs; (void)frac; (void)scale; (void)tick_per_sec;
}

void commpage_update_boottime(uint64_t boottime_usec)
{
    (void)boottime_usec;
}

void commpage_update_mach_continuous_time(uint64_t sleeptime)
{
    (void)sleeptime;
}

void commpage_set_nanotime(uint64_t tsc_base, uint64_t ns_base,
    uint32_t scale, uint32_t shift)
{
    (void)tsc_base; (void)ns_base; (void)scale; (void)shift;
}

void ntp_init(void) {}

void ntp_update_second(int64_t *adjustment, clock_sec_t second)
{
    (void)adjustment; (void)second;
}

/* ── PE (Platform Expert) time — stub; dtape clock subsystem handles real time */

void PEGetUTCTimeOfDay(clock_sec_t *secs, clock_usec_t *usecs)
{
    *secs = 0; *usecs = 0;
}

void PESetUTCTimeOfDay(clock_sec_t secs, clock_usec_t usecs)
{
    (void)secs; (void)usecs;
}

/* ── kernel_sysctlbyname — stub; real sysctl not available in kernel ctx ── */

int kernel_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    void *newp, size_t newlen)
{
    (void)name; (void)oldp; (void)oldlenp; (void)newp; (void)newlen;
    return -1;
}

/* ── os_log stubs ───────────────────────────────────────────────────────── */

/* os_log_t is declared in XNU headers; _os_log_default is a global pointer */
void *_os_log_default = (void *)0; /* NULL = disabled */

void _os_log_internal(void *dso, void *log, int type, const char *fmt, ...)
{
    (void)dso; (void)log; (void)type; (void)fmt;
}

/* ── thread_interrupt_level ─────────────────────────────────────────────── */

int thread_interrupt_level(int new_level)
{
    (void)new_level;
    return 0; /* THREAD_UNINT = 0 */
}

/* ── sysinfo (Linux syscall — stub with zeros for FreeBSD) ─────────────── */

/* struct sysinfo matches Linux ABI; declared in dtape/src/host.c */
struct sysinfo {
    long           uptime;
    unsigned long  loads[3];
    unsigned long  totalram;
    unsigned long  freeram;
    unsigned long  sharedram;
    unsigned long  bufferram;
    unsigned long  totalswap;
    unsigned long  freeswap;
    unsigned short procs;
    unsigned long  totalhigh;
    unsigned long  freehigh;
    unsigned int   mem_unit;
    char _f[20 - 2 * sizeof(long) - sizeof(int)];
};

int sysinfo(struct sysinfo *info)
{
    if (!info) return -1;
    __builtin_memset(info, 0, sizeof(*info));
    info->mem_unit = 1;
    return 0;
}

/* ── x86 PAL / rtclock stubs ─────────────────────────────────────────────── */

#include <i386/rtclock_protos.h>
#include <i386/pal_routines.h>
#include <i386/tsc.h>
#include <kern/timer_queue.h>

/* TSC frequency: non-zero to pass assert(tscFreq); 3GHz is a safe placeholder */
uint64_t tscFreq   = 3000000000ULL;
uint64_t tsc_at_boot = 0;

/* rtc_timer: needs non-null function pointers to avoid crash on rtc_config() */
static void     rtc_config_nop(void) {}
static uint64_t rtc_set_nop(uint64_t a, uint64_t b) { (void)a; (void)b; return 0; }
static rtc_timer_t _rtc_timer_stub = {
    .rtc_config = rtc_config_nop,
    .rtc_set    = rtc_set_nop,
};
rtc_timer_t *rtc_timer = &_rtc_timer_stub;

/* PAL nanotime store: no-op (userspace dtape provides clock via mach_absolute_time) */
void _pal_rtc_nanotime_store(uint64_t tsc, uint64_t nsec,
    uint32_t scale, uint32_t shift,
    struct pal_rtc_nanotime *dst)
{
    (void)tsc; (void)nsec; (void)scale; (void)shift; (void)dst;
}

uint64_t _rtc_tsc_to_nanoseconds(uint64_t value,
    pal_rtc_nanotime_t *rntp)
{
    (void)rntp;
    /* crude: 1 TSC tick ≈ 1/3GHz ≈ 0.33 ns; close enough for stubs */
    return value / 3;
}

void _rtc_nanotime_adjust(uint64_t tsc_base_delta,
    pal_rtc_nanotime_t *dst)
{
    (void)tsc_base_delta; (void)dst;
}

/* timer_intr: called from rtclock_intr on x86 hardware interrupt; no-op here */
void timer_intr(int inuser, uint64_t iaddr)
{
    (void)inuser; (void)iaddr;
}

/* ── XNU task stubs (defined in task.c / task_policy.c, excluded from build) */

#include <kern/task.h>
#include <kern/policy_internal.h>

void task_dyld_process_info_update_helper(task_t task,
    size_t active_count, vm_map_address_t magic_addr,
    ipc_port_t *release_ports, size_t release_count)
{
    (void)task; (void)active_count; (void)magic_addr;
    (void)release_ports; (void)release_count;
}

void task_importance_reset(task_t task)
{
    (void)task;
}

/* ── kalloc heap stubs ───────────────────────────────────────────────────── */
/* KALLOC_HEAP_DECLARE(X) expands to: extern struct kalloc_heap X[1].
 * Define them as BSS so kalloc_ext() callers get a non-null heap pointer. */
#include <kern/kalloc.h>
struct kalloc_heap KHEAP_TEMP[1];    /* temporary (scoped) allocation heap */

/* ── dyldinfo mutex ─────────────────────────────────────────────────────── */
/* g_dyldinfo_mtx: protects task_dyld_process_info_notify_get_trap internals */
lck_mtx_t g_dyldinfo_mtx;   /* zero-initialized; lck_mtx_init() not called —
                               * notify_get_trap is stubbed so lock is unreachable */

/* ── VM copyout stubs ────────────────────────────────────────────────────── */
#include <vm/vm_kern.h>

kern_return_t copyoutmap_atomic32(vm_map_t map, uint32_t value,
    vm_map_offset_t toaddr)
{
    (void)map; (void)value; (void)toaddr;
    return KERN_NOT_SUPPORTED;
}

/* ── Additional task stubs ───────────────────────────────────────────────── */

void task_bsdtask_kill(task_t task)
{
    (void)task;
}

kern_return_t task_violated_guard(mach_exception_code_t code,
    mach_exception_subcode_t subcode, void *state)
{
    (void)code; (void)subcode; (void)state;
    return KERN_SUCCESS;
}
