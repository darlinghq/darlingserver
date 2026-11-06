#!/usr/bin/env bash
# Build the unknown-flavor (default) cases of mach_vm_region() and thread_info()
# on the host and check they return KERN_INVALID_ARGUMENT instead of aborting.
# Usage: tests/region-thread-info-flavors.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
src() {
    if [[ -n ${rev:-} ]]; then git -C "$root" show "$rev:duct-tape/src/$1"; else cat "$root/duct-tape/src/$1"; fi
}
rev=${1:-}
# The default case of the function's top-level switch, through the switch's closing brace.
default_case() {
    awk -v sig="^kern_return_t $1\\\\(" '
        $0 ~ sig { infn = 1 }
        infn && /^\t\tdefault:$/ { grab = 1 }
        grab { print }
        grab && /^\t}$/ { exit }
    '
}
region=$(src memory.c | default_case mach_vm_region)
thread=$(src thread.c | default_case thread_info)
[[ -n $region && -n $thread ]] || { echo "default case not found" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values from duct-tape/xnu/osfmk/mach/kern_return.h, vm_region.h and thread_info.h. */
#define KERN_INVALID_ARGUMENT 4
#define VM_REGION_TOP_INFO 12
#define VM_REGION_EXTENDED_INFO 13
#define THREAD_EXTENDED_INFO 5
#define THREAD_SCHED_TIMESHARE_INFO 10
#define IP_NULL ((mach_port_t)0)
typedef int kern_return_t, vm_region_flavor_t;
typedef unsigned int thread_flavor_t, mach_port_t;
#define dtape_log_debug(...) ((void)0)
/* In darlingserver this logs and reaches __builtin_unreachable(): the server dies. */
#define dtape_stub_unsafe(...) (fprintf(stderr, "FAIL: %s reaches dtape_stub_unsafe (server abort)\n", __func__), exit(1), 0)

static kern_return_t mach_vm_region(vm_region_flavor_t flavor, mach_port_t* object_name) {
	switch (flavor) {
C
printf '%s\n' "$region" >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'
	return -2;
}

static kern_return_t thread_info(thread_flavor_t flavor) {
	switch (flavor) {
C
printf '%s\n' "$thread" >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'
	return -2;
}

int main(void) {
    const vm_region_flavor_t regions[] = { VM_REGION_TOP_INFO, VM_REGION_EXTENDED_INFO, 0x7fff };
    for (unsigned i = 0; i < sizeof(regions) / sizeof(regions[0]); ++i) {
        mach_port_t name = 0x1234;
        CHECK(mach_vm_region(regions[i], &name) == KERN_INVALID_ARGUMENT);
        CHECK(name == IP_NULL);
        CHECK(mach_vm_region(regions[i], NULL) == KERN_INVALID_ARGUMENT);
    }
    const thread_flavor_t threads[] = { THREAD_EXTENDED_INFO, THREAD_SCHED_TIMESHARE_INFO, 0xffffffffu };
    for (unsigned i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i)
        CHECK(thread_info(threads[i]) == KERN_INVALID_ARGUMENT);
    puts("PASS: mach_vm_region and thread_info reject unknown flavors with KERN_INVALID_ARGUMENT");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
