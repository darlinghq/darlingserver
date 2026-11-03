#!/usr/bin/env bash
# Build the real x86_DEBUG_STATE32 case of thread_set_state on the host and
# check that it forwards the widened 64-bit registers, not its own pointer.
# Usage: tests/x86-debug-state32-forward.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/thread.c")
else
    source=$(cat "$root/duct-tape/src/thread.c")
fi
# The case block inside thread_set_state(), from its label to its closing brace.
block=$(awk '
    /^thread_set_state\($/ { infn = 1 }
    infn && /^\t\t\tcase x86_DEBUG_STATE32:$/ { grab = 1 }
    grab { print }
    grab && /^\t\t\t}$/ { exit }
' <<<"$source")
[[ -n $block ]] || { echo "x86_DEBUG_STATE32 case not found" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values and layouts from duct-tape/xnu/osfmk/mach/i386/thread_status.h and _structs.h. */
#define KERN_SUCCESS 0
#define KERN_INVALID_ARGUMENT 4
#define x86_DEBUG_STATE32 10
#define x86_DEBUG_STATE64 11
typedef int kern_return_t;
typedef unsigned int natural_t, mach_msg_type_number_t, *thread_state_t;
typedef struct { unsigned int dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7; } x86_debug_state32_t;
typedef struct { uint64_t dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7; } x86_debug_state64_t;
#define x86_DEBUG_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(x86_debug_state64_t) / sizeof(unsigned int)))
enum { dserver_rpc_architecture_i386 = 1, dserver_rpc_architecture_x86_64 = 2 };
struct dtask { int architecture; };
typedef void *thread_t;

static int forwarded;
static kern_return_t forward(thread_t thread, int flavor, thread_state_t state, mach_msg_type_number_t count) {
    (void)thread;
    CHECK(flavor == x86_DEBUG_STATE64);
    CHECK(count == x86_DEBUG_STATE64_COUNT);
    const uint64_t *regs = (const uint64_t *)state;
    /* Stop at the first mismatch so a wrong pointer is not read past its end. */
    for (int i = 0; i < 8; ++i) {
        if (regs[i] != 0x10u + (uint64_t)i) {
            fprintf(stderr, "FAIL: forwarded dr%d = %#llx, expected %#x\n", i,
                    (unsigned long long)regs[i], 0x10 + i);
            return -1;
        }
    }
    forwarded++;
    return KERN_SUCCESS;
}
#define thread_set_state forward

static kern_return_t set_debug32(thread_t thread, struct dtask *dtask, thread_state_t state) {
    switch (x86_DEBUG_STATE32) {
C
printf '%s\n' "$block" >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'
    }
    return -2;
}

int main(void) {
    x86_debug_state32_t s32 = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    struct dtask task32 = { dserver_rpc_architecture_i386 }, task64 = { dserver_rpc_architecture_x86_64 };
    CHECK(set_debug32(NULL, &task64, (thread_state_t)&s32) == KERN_INVALID_ARGUMENT);
    CHECK(forwarded == 0);
    if (set_debug32(NULL, &task32, (thread_state_t)&s32) != KERN_SUCCESS)
        return 1;
    CHECK(forwarded == 1);
    puts("PASS: x86_DEBUG_STATE32 forwards the widened registers as x86_DEBUG_STATE64");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
