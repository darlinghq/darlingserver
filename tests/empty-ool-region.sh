#!/usr/bin/env bash
# Build the real out-of-line memory accounting check of ipc_kmsg_copyin_body
# on the host and check that an empty region is accepted.
# Usage: tests/empty-ool-region.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
read_source() {
    if [[ -n $rev ]]; then git -C "$root" show "$rev:$1"; else cat "$root/$1"; fi
}
rev=${1:-}
kmsg=$(read_source duct-tape/xnu/osfmk/ipc/ipc_kmsg.c)
memory=$(read_source duct-tape/src/memory.c)

# The physical-copy accounting block in ipc_kmsg_copyin_body(), from its if to its closing brace.
block=$(awk '
    /^ipc_kmsg_copyin_body\($/ { infn = 1 }
    infn && /\(size >= MSG_OOL_SIZE_SMALL\)/ { grab = 1 }
    grab { print }
    grab && /^\t\t\t}$/ { exit }
' <<<"$kmsg")
[[ -n $block ]] || { echo "OOL accounting block not found" >&2; exit 2; }
# Darling's kalloc_max_prerounded, which ipc_init() uses for msg_ool_size_small.
prerounded=$(sed -n 's/^vm_size_t kalloc_max_prerounded = \(.*\);$/\1/p' <<<"$memory")
[[ -n $prerounded ]] || { echo "kalloc_max_prerounded initializer not found" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<C
#define KALLOC_MAX_PREROUNDED ($prerounded)
C
cat >>"$work/harness.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values from duct-tape/xnu/osfmk/mach/message.h and ipc/ipc_init.c. */
#define MACH_MSG_SUCCESS 0
#define MACH_MSG_VM_KERNEL 0x400
#define MACH_MSG_PHYSICAL_COPY 0
#define MACH_MSG_VIRTUAL_COPY 1
#define PAGE_SIZE 4096
#define round_page(x) (((x) + PAGE_SIZE - 1) & ~(vm_size_t)(PAGE_SIZE - 1))
#define MSG_OOL_SIZE_SMALL_MAX (2 * PAGE_SIZE)
typedef uint64_t vm_size_t;
typedef int mach_msg_return_t;
static const vm_size_t ipc_kmsg_max_vm_space = (8 * 1024 * 1024 * 7) / 8;
/* ipc_init(): the smaller of kalloc_max_prerounded and MSG_OOL_SIZE_SMALL_MAX. */
static const vm_size_t msg_ool_size_small =
    KALLOC_MAX_PREROUNDED <= MSG_OOL_SIZE_SMALL_MAX ? KALLOC_MAX_PREROUNDED : MSG_OOL_SIZE_SMALL_MAX;
#define MSG_OOL_SIZE_SMALL msg_ool_size_small

static mach_msg_return_t account(vm_size_t size, int copy, int deallocate, vm_size_t *space) {
    struct { struct { int copy, deallocate; } out_of_line; } d = { { copy, deallocate } }, *daddr = &d;
    vm_size_t space_needed = *space;
    mach_msg_return_t mr = MACH_MSG_SUCCESS;
C
printf '%s\n' "$block" >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'
    *space = space_needed;
    return mr;
clean_message:
    return mr;
}

int main(void) {
    vm_size_t space = 0;
    CHECK(account(0, MACH_MSG_PHYSICAL_COPY, 0, &space) == MACH_MSG_SUCCESS);
    CHECK(space == 0);
    /* An empty region after a non-empty one leaves the total unchanged. */
    CHECK(account(1, MACH_MSG_PHYSICAL_COPY, 0, &space) == MACH_MSG_SUCCESS);
    CHECK(space == (msg_ool_size_small <= 1 ? PAGE_SIZE : 0));
    vm_size_t before = space;
    CHECK(account(0, MACH_MSG_PHYSICAL_COPY, 0, &space) == MACH_MSG_SUCCESS);
    CHECK(space == before);
    /* The per-message limit and the virtual-copy and deallocate exemptions are unchanged. */
    space = 0;
    CHECK(account(ipc_kmsg_max_vm_space + 1, MACH_MSG_PHYSICAL_COPY, 0, &space) == MACH_MSG_VM_KERNEL);
    space = 0;
    CHECK(account(ipc_kmsg_max_vm_space + 1, MACH_MSG_VIRTUAL_COPY, 0, &space) == MACH_MSG_SUCCESS);
    CHECK(account(ipc_kmsg_max_vm_space + 1, MACH_MSG_PHYSICAL_COPY, 1, &space) == MACH_MSG_SUCCESS);
    CHECK(space == 0);
    printf("PASS: empty OOL regions need no kernel copy space (msg_ool_size_small = %llu)\n",
           (unsigned long long)msg_ool_size_small);
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
