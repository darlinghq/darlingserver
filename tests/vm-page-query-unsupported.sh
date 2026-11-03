#!/usr/bin/env bash
# Build the real mach_vm_page_info/_query/_range_query from duct-tape/src/memory.c
# on the host and check they return errors instead of aborting the server.
# Usage: tests/vm-page-query-unsupported.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/memory.c")
else
    source=$(cat "$root/duct-tape/src/memory.c")
fi
# Each function from its signature line to its closing "};".
extract() {
    awk -v sig="^kern_return_t $1\\\\(" '
        $0 ~ sig { grab = 1 }
        grab { print }
        grab && /^};$/ { exit }
    ' <<<"$source"
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values from duct-tape/xnu/osfmk/mach/kern_return.h and mach/vm_region.h. */
#define KERN_INVALID_ARGUMENT 4
#define KERN_NOT_SUPPORTED 46
#define VM_PAGE_INFO_BASIC 1
#define VM_PAGE_INFO_BASIC_COUNT ((mach_msg_type_number_t)(sizeof(vm_page_info_basic_data_t) / sizeof(int)))
typedef int kern_return_t, vm_page_info_flavor_t, *vm_page_info_t;
typedef unsigned int mach_msg_type_number_t;
typedef uint64_t mach_vm_address_t, mach_vm_offset_t, mach_vm_size_t;
typedef struct { int disposition, ref_count; uint64_t object_id, offset; int depth, __pad; } vm_page_info_basic_data_t;
typedef struct vm_map *vm_map_t;
/* In darlingserver this logs and reaches __builtin_unreachable(): the server dies. */
#define dtape_stub_unsafe(...) (fprintf(stderr, "FAIL: %s reaches dtape_stub_unsafe (server abort)\n", __func__), exit(1), 0)
C
for fn in mach_vm_page_info mach_vm_page_query mach_vm_page_range_query; do
    body=$(extract "$fn")
    [[ -n $body ]] || { echo "$fn not found" >&2; exit 2; }
    printf '%s\n' "$body" >>"$work/harness.c"
done
cat >>"$work/harness.c" <<'C'

int main(void) {
    vm_map_t map = (vm_map_t)0x1000;
    vm_page_info_basic_data_t info;
    mach_msg_type_number_t count;

    /* Unknown flavors and wrong counts: XNU's vm_map_page_range_info_internal() rejects them. */
    count = VM_PAGE_INFO_BASIC_COUNT;
    CHECK(mach_vm_page_info(map, 0x2000, 2, (vm_page_info_t)&info, &count) == KERN_INVALID_ARGUMENT);
    count = VM_PAGE_INFO_BASIC_COUNT - 2;
    CHECK(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&info, &count) == KERN_INVALID_ARGUMENT);
    /* The supported flavor (both accepted counts) is reported as not supported, with nothing returned. */
    count = VM_PAGE_INFO_BASIC_COUNT;
    CHECK(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&info, &count) == KERN_NOT_SUPPORTED);
    CHECK(count == 0);
    count = VM_PAGE_INFO_BASIC_COUNT - 1;
    CHECK(mach_vm_page_info(map, 0x2000, VM_PAGE_INFO_BASIC, (vm_page_info_t)&info, &count) == KERN_NOT_SUPPORTED);
    CHECK(count == 0);

    /* XNU's vm_map_page_query_internal() zeroes both outputs on failure. */
    int disposition = -1, ref_count = -1;
    CHECK(mach_vm_page_query(map, 0x2000, &disposition, &ref_count) == KERN_NOT_SUPPORTED);
    CHECK(disposition == 0 && ref_count == 0);

    mach_vm_size_t dispositions = 4;
    CHECK(mach_vm_page_range_query(map, 0x2000, 0x4000, 0x8000, &dispositions) == KERN_NOT_SUPPORTED);
    CHECK(dispositions == 0);

    puts("PASS: mach_vm page queries reject unsupported requests with error codes");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
