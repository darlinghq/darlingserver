#!/usr/bin/env bash
# Build the real dtape_thread_load_state_from_user() and dtape_thread_save_state_to_user()
# on the host, under ASan, and check that they copy the task's thread state only when the
# caller's buffers have the task's layout.
# Usage: tests/thread-state-caller-architecture.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [[ $# -ge 1 ]]; then
    git -C "$root" show "$1:duct-tape/src/thread.c" >"$work/thread.c"
else
    cp "$root/duct-tape/src/thread.c" "$work/thread.c"
fi
extract=$root/tests/host/extract-static.sh
{
    # Older revisions have no caller architecture parameter; call them the old way.
    if grep -q '^static bool dtape_thread_user_state_matches_task(' "$work/thread.c"; then
        sh "$extract" "$work/thread.c" dtape_thread_user_state_matches_task
        echo '#define STATE_ARGS(arch, t, f) (arch), (t), (f)'
    else
        echo '#define STATE_ARGS(arch, t, f) (t), (f)'
    fi
    sh "$extract" "$work/thread.c" dtape_thread_load_state_from_user dtape_thread_save_state_to_user
} >"$work/state.inc"

cat >"$work/harness.c" <<'C'
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)

/* Sizes from duct-tape/xnu/osfmk/mach/{i386,arm}/_structs.h; only the sizes matter here. */
typedef struct { uint64_t r[21]; } x86_thread_state64_t;                     /* 168 */
typedef struct { unsigned char b[524]; } x86_float_state64_t;                /* 524 */
typedef struct { uint32_t r[16]; } x86_thread_state32_t;                     /* 64 */
typedef struct { unsigned char b[524]; } x86_float_state32_t;                /* 524 */
typedef struct { uint64_t r[34]; } arm_thread_state64_t;                     /* 272 */
typedef struct { __uint128_t v[32]; uint32_t fpsr, fpcr; } arm_neon_state64_t; /* 528 */
_Static_assert(sizeof(x86_thread_state64_t) == 168 && sizeof(arm_thread_state64_t) == 272, "sizes");
_Static_assert(sizeof(x86_float_state64_t) == 524 && sizeof(arm_neon_state64_t) == 528, "sizes");

enum { x86_THREAD_STATE32 = 1, x86_FLOAT_STATE32, x86_THREAD_STATE64, x86_FLOAT_STATE64,
       ARM_THREAD_STATE64, ARM_NEON_STATE64 };
#define x86_THREAD_STATE64_COUNT (sizeof(x86_thread_state64_t) / 4)
#define x86_FLOAT_STATE64_COUNT (sizeof(x86_float_state64_t) / 4)
#define x86_THREAD_STATE32_COUNT (sizeof(x86_thread_state32_t) / 4)
#define x86_FLOAT_STATE32_COUNT (sizeof(x86_float_state32_t) / 4)
#define ARM_THREAD_STATE64_COUNT (sizeof(arm_thread_state64_t) / 4)
#define ARM_NEON_STATE64_COUNT (sizeof(arm_neon_state64_t) / 4)
#define LINUX_EFAULT 14
#define LINUX_ENOSYS 38

typedef enum { dserver_rpc_architecture_invalid, dserver_rpc_architecture_i386, dserver_rpc_architecture_x86_64,
               dserver_rpc_architecture_arm32, dserver_rpc_architecture_arm64 } dserver_rpc_architecture_t;
typedef int kern_return_t;
typedef unsigned int mach_msg_type_number_t, *thread_state_t;
typedef void *thread_t;
typedef struct { dserver_rpc_architecture_t architecture; } dtape_task_t;
typedef struct { int unused; } dtape_thread_t;

static dtape_task_t the_task;
static dtape_task_t *dtape_task_for_thread(dtape_thread_t *thread) { (void)thread; return &the_task; }
static thread_t current_thread(void) { return NULL; }
#define dtape_log_error(...) ((void)0)
#define dtape_log_debug(...) ((void)0)

/* The task's saved state, as thread_set_state() keeps it. */
static unsigned char saved[2][1024];
static int copies;
static int copyin(uintptr_t user, void *kernel, size_t n) { copies++; memcpy(kernel, (const void *)user, n); return 0; }
static int copyout(const void *kernel, uintptr_t user, size_t n) { copies++; memcpy((void *)user, kernel, n); return 0; }
static int is_float(int flavor) {
    return flavor == x86_FLOAT_STATE64 || flavor == x86_FLOAT_STATE32 || flavor == ARM_NEON_STATE64;
}
static kern_return_t thread_set_state(thread_t t, int flavor, thread_state_t s, mach_msg_type_number_t count) {
    (void)t; memcpy(saved[is_float(flavor)], s, count * 4); return 0;
}
static kern_return_t thread_get_state(thread_t t, int flavor, thread_state_t s, mach_msg_type_number_t *count) {
    (void)t; memcpy(s, saved[is_float(flavor)], *count * 4); return 0;
}

#include STATE_INC

#if defined(__aarch64__)
static const dserver_rpc_architecture_t native = dserver_rpc_architecture_arm64, foreign = dserver_rpc_architecture_x86_64;
static const size_t native_sizes[2] = { sizeof(arm_thread_state64_t), sizeof(arm_neon_state64_t) };
static const size_t foreign_sizes[2] = { sizeof(x86_thread_state64_t), sizeof(x86_float_state64_t) };
#elif defined(__x86_64__)
static const dserver_rpc_architecture_t native = dserver_rpc_architecture_x86_64, foreign = dserver_rpc_architecture_arm64;
static const size_t native_sizes[2] = { sizeof(x86_thread_state64_t), sizeof(x86_float_state64_t) };
static const size_t foreign_sizes[2] = { sizeof(arm_thread_state64_t), sizeof(arm_neon_state64_t) };
#else
#error "host architecture not covered"
#endif

/* Exact-size heap buffers, so ASan reports any access past the caller's buffer. */
static unsigned char *buffer(size_t n, unsigned char fill) {
    unsigned char *b = malloc(n);
    CHECK(b != NULL);
    memset(b, fill, n);
    return b;
}

/* Each case prints its name first, so an ASan report or CHECK failure is attributed to it. */
static void begin(const char *name) { printf("CASE: %s\n", name); fflush(stdout); copies = 0; }

static void native_round_trip(void) {
    dtape_thread_t thread;
    unsigned char *t = buffer(native_sizes[0], 0x11), *f = buffer(native_sizes[1], 0x22);
    begin("native caller loads and saves");
    CHECK(dtape_thread_load_state_from_user(&thread, STATE_ARGS(native, (uintptr_t)t, (uintptr_t)f)) == 0);
    CHECK(copies == 2 && saved[0][0] == 0x11 && saved[1][0] == 0x22);
    /* A debugger changes the state while the thread waits in the server. */
    memset(saved, 0x5a, sizeof(saved));
    CHECK(dtape_thread_save_state_to_user(&thread, STATE_ARGS(native, (uintptr_t)t, (uintptr_t)f)) == 0);
    CHECK(copies == 4);
    CHECK(t[0] == 0x5a && t[native_sizes[0] - 1] == 0x5a && f[0] == 0x5a && f[native_sizes[1] - 1] == 0x5a);
    free(t);
    free(f);
}

static void check_untouched(const unsigned char *b, size_t n, unsigned char fill) {
    for (size_t i = 0; i < n; i++) CHECK(b[i] == fill);
}

static void foreign_load(void) {
    dtape_thread_t thread;
    unsigned char *t = buffer(foreign_sizes[0], 0x33), *f = buffer(foreign_sizes[1], 0x44);
    memset(saved, 0x5a, sizeof(saved));
    begin("foreign caller: load reads nothing");
    CHECK(dtape_thread_load_state_from_user(&thread, STATE_ARGS(foreign, (uintptr_t)t, (uintptr_t)f)) == 0);
    CHECK(copies == 0);
    CHECK(saved[0][0] == 0x5a && saved[1][0] == 0x5a);
    free(t);
    free(f);
}

static void foreign_save(void) {
    dtape_thread_t thread;
    unsigned char *t = buffer(foreign_sizes[0], 0x33), *f = buffer(foreign_sizes[1], 0x44);
    memset(saved, 0x5a, sizeof(saved));
    begin("foreign caller: save writes nothing");
    CHECK(dtape_thread_save_state_to_user(&thread, STATE_ARGS(foreign, (uintptr_t)t, (uintptr_t)f)) == 0);
    CHECK(copies == 0);
    check_untouched(t, foreign_sizes[0], 0x33);
    check_untouched(f, foreign_sizes[1], 0x44);
    free(t);
    free(f);
}

int main(void) {
    the_task.architecture = native;
    native_round_trip();
    foreign_load();
    foreign_save();
    puts("PASS: a native caller transfers the state; an emulated caller's buffers are neither read nor written");
    return 0;
}
C
${CC:-cc} -std=gnu11 -g -O0 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -Wall -Wno-unused-function -DSTATE_INC="\"$work/state.inc\"" "$work/harness.c" -o "$work/harness"
"$work/harness"
