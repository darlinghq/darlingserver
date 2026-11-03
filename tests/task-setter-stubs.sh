#!/usr/bin/env bash
# Build the real task_set_exc_guard_behavior() and task_set_phys_footprint_limit()
# from duct-tape/src/task.c on the host and check XNU's return codes, with
# task_get_exc_guard_behavior() reading back what was set.
# Usage: tests/task-setter-stubs.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/task.c")
else
    source=$(cat "$root/duct-tape/src/task.c")
fi
# A function from its signature line ("kern_return_t name(" or a bare "name(")
# to its closing brace.
extract() {
    awk -v sig="^(kern_return_t )?$1\\\\(" '
        $0 ~ sig { grab = 1; if (prev ~ /^kern_return_t$/) print prev }
        grab { print }
        grab && /^};?$/ { exit }
        { prev = $0 }
    ' <<<"$source"
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values from duct-tape/xnu/osfmk/mach/kern_return.h and mach/task_info.h. */
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define KERN_INVALID_TASK 16
#define KERN_INVALID_VALUE 18
#define TASK_EXC_GUARD_VM_DELIVER 0x01
#define TASK_EXC_GUARD_MP_FATAL 0x80
#define TASK_EXC_GUARD_ALL 0xff
#define TASK_NULL ((task_t)0)
typedef int kern_return_t;
typedef uint32_t task_exc_guard_behavior_t;
typedef struct task { task_exc_guard_behavior_t task_exc_guard; } *task_t;
/* In darlingserver this logs and reaches __builtin_unreachable(): the server dies. */
#define dtape_stub_unsafe(...) (fprintf(stderr, "FAIL: %s reaches dtape_stub_unsafe (server abort)\n", __func__), exit(1), 0)
C
for fn in task_set_exc_guard_behavior task_get_exc_guard_behavior task_set_phys_footprint_limit; do
    body=$(extract "$fn")
    [[ -n $body ]] || { echo "$fn not found" >&2; exit 2; }
    printf '%s\n' "$body" >>"$work/harness.c"
done
cat >>"$work/harness.c" <<'C'

int main(void) {
    struct task task = { 0 };
    task_exc_guard_behavior_t behavior = 0;

    /* XNU without CONFIG_MEMORYSTATUS: KERN_FAILURE, old limit untouched. */
    int old_limit = 1234;
    CHECK(task_set_phys_footprint_limit(&task, 100, &old_limit) == KERN_FAILURE);
    CHECK(old_limit == 1234);

    /* XNU's task_set_exc_guard_behavior(): store valid bits, reject others. */
    CHECK(task_set_exc_guard_behavior(&task, TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_MP_FATAL) == KERN_SUCCESS);
    CHECK(task_get_exc_guard_behavior(&task, &behavior) == KERN_SUCCESS);
    CHECK(behavior == (TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_MP_FATAL));
    CHECK(task_set_exc_guard_behavior(&task, TASK_EXC_GUARD_ALL + 1) == KERN_INVALID_VALUE);
    CHECK(task_get_exc_guard_behavior(&task, &behavior) == KERN_SUCCESS);
    CHECK(behavior == (TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_MP_FATAL));
    CHECK(task_set_exc_guard_behavior(&task, 0) == KERN_SUCCESS);
    CHECK(task.task_exc_guard == 0);
    CHECK(task_set_exc_guard_behavior(TASK_NULL, 0) == KERN_INVALID_TASK);

    puts("PASS: task_set_exc_guard_behavior and task_set_phys_footprint_limit follow XNU");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
