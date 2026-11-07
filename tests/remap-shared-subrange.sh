#!/usr/bin/env bash
# Build the real mach_vm_remap_external_shared() and dtape_map_find_shared_entries_locked()
# from duct-tape/src/memory.c on the host and check that a shared remap of the first page of a
# region that is already shared reuses the existing shared object, one page long.
# Usage: tests/remap-shared-subrange.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/memory.c")
else
    source=$(cat "$root/duct-tape/src/memory.c")
fi
# Each function from its definition line to its closing "};".
extract() {
    awk -v sig="^(static )?[a-z_]+ $1\\\\(" '
        $0 ~ sig { grab = 1 }
        grab { print }
        grab && /^};$/ { exit }
    ' <<<"$source"
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Values from duct-tape/xnu/osfmk/mach/kern_return.h, mach/vm_prot.h and mach/vm_statistics.h. */
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define KERN_RESOURCE_SHORTAGE 6
#define VM_PROT_NONE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_ALL 7
#define VM_FLAGS_ANYWHERE 0x0001
#define VM_FLAGS_RETURN_DATA_ADDR 0x100000
typedef int kern_return_t, vm_prot_t;
typedef unsigned int vm_inherit_t;
typedef uint64_t mach_vm_offset_t, mach_vm_size_t, vm_map_address_t;
/* duct-tape/include/darlingserver/duct-tape/types.h */
typedef enum { dtape_memory_protection_read = 1 << 0, dtape_memory_protection_write = 1 << 1, dtape_memory_protection_execute = 1 << 2 } dtape_memory_protection_t;
typedef struct { uintptr_t start_address; uint64_t page_count, map_offset; dtape_memory_protection_t protection; bool shared; } dtape_memory_region_info_t;
typedef enum { dtape_memory_flag_none = 0, dtape_memory_flag_fixed = 1 << 0, dtape_memory_flag_overwrite = 1 << 1 } dtape_memory_flags_t;

/* Stand-ins for the shared-entry bookkeeping (an RB tree in darlingserver; a sorted array is enough here). */
typedef struct { int refcount; int memfd; uint64_t size; } dtape_map_shared_descriptor_t;
typedef struct dtape_map_shared_entry { uint64_t address, size, page_offset; dtape_map_shared_descriptor_t* descriptor; } dtape_map_shared_entry_t;
struct entry_set { size_t count; dtape_map_shared_entry_t* entries[16]; };
#define RB_FOREACH(entry, name, set) for (size_t i_ = 0; i_ < (set)->count && ((entry) = (set)->entries[i_], 1); i_++)
struct dtape_task { void* context; };
typedef struct dtape_map { struct dtape_task* dtape_task; struct entry_set shared_entries; int shared_entry_lock; } dtape_map_t, *vm_map_t;
static void dtape_mutex_lock(int* m) { (void)m; }
static void dtape_mutex_unlock(int* m) { (void)m; }

static uint64_t page_size(void) { return (uint64_t)sysconf(_SC_PAGESIZE); }
#define mach_vm_round_page(x) (((x) + page_size() - 1) & ~(page_size() - 1))
#define mach_vm_trunc_page(x) ((x) & ~(page_size() - 1))
static uint64_t dtape_byte_count_to_page_count_round_up(uint64_t bytes) { return (bytes + page_size() - 1) / page_size(); }

static dtape_map_shared_descriptor_t* dtape_map_shared_descriptor_create(int memfd, uint64_t size) {
    dtape_map_shared_descriptor_t* desc = malloc(sizeof(*desc));
    desc->refcount = 1;
    desc->memfd = memfd;
    desc->size = size;
    return desc;
}
static void dtape_map_shared_descriptor_retain(dtape_map_shared_descriptor_t* desc) { desc->refcount++; }
static void dtape_map_shared_descriptor_release(dtape_map_shared_descriptor_t* desc) {
    if (--desc->refcount == 0) {
        close(desc->memfd);
        free(desc);
    }
}
static dtape_map_shared_entry_t* dtape_map_shared_entry_create(uint64_t address, uint64_t size, uint64_t page_offset, dtape_map_shared_descriptor_t* desc) {
    dtape_map_shared_entry_t* entry = malloc(sizeof(*entry));
    *entry = (dtape_map_shared_entry_t){ address, size, page_offset, desc };
    dtape_map_shared_descriptor_retain(desc);
    return entry;
}
static void dtape_map_shared_entry_destroy(dtape_map_shared_entry_t* entry) {
    dtape_map_shared_descriptor_release(entry->descriptor);
    free(entry);
}
static dtape_map_shared_entry_t* last_inserted;
static void dtape_map_insert_shared_entry(dtape_map_t* map, dtape_map_shared_entry_t* entry) {
    struct entry_set* set = &map->shared_entries;
    size_t i = set->count++;
    CHECK(set->count <= sizeof(set->entries) / sizeof(*set->entries));
    while (i > 0 && set->entries[i - 1]->address > entry->address) {
        set->entries[i] = set->entries[i - 1];
        i--;
    }
    set->entries[i] = entry;
    last_inserted = entry;
}

/* The "task" is this process: its memory is accessed directly. */
/* Where the next "anywhere" mapping goes, if set: lets the test place it the way Linux places it in a guest. */
static uintptr_t next_anywhere;
static bool hook_region_info(void* ctx, uintptr_t address, dtape_memory_region_info_t* info) {
    (void)ctx; (void)address;
    memset(info, 0, sizeof(*info));
    info->protection = dtape_memory_protection_read | dtape_memory_protection_write;
    return true;
}
static uintptr_t hook_map_file(void* ctx, int fd, uint64_t page_count, int prot, uintptr_t address, uint64_t page_offset, dtape_memory_flags_t flags) {
    (void)ctx;
    if (!(flags & dtape_memory_flag_fixed) && next_anywhere) {
        address = next_anywhere;
        flags |= dtape_memory_flag_fixed;
        next_anywhere = 0;
    }
    void* p = mmap((void*)address, page_count * page_size(), prot, MAP_SHARED | ((flags & dtape_memory_flag_fixed) ? MAP_FIXED : 0), fd, page_offset * page_size());
    return p == MAP_FAILED ? 0 : (uintptr_t)p;
}
static struct {
    bool (*task_get_memory_region_info)(void*, uintptr_t, dtape_memory_region_info_t*);
    uintptr_t (*task_map_file)(void*, int, uint64_t, int, uintptr_t, uint64_t, dtape_memory_flags_t);
} hooks = { hook_region_info, hook_map_file }, *dtape_hooks = &hooks;
static kern_return_t copyinmap(vm_map_t map, uintptr_t from, void* to, size_t length) {
    (void)map;
    memcpy(to, (void*)from, length);
    return KERN_SUCCESS;
}
#define dtape_log_error(...) fprintf(stderr, __VA_ARGS__)
/* In darlingserver this logs and reaches __builtin_unreachable(): the server dies. */
#define dtape_stub_unsafe(...) (fprintf(stderr, "FAIL: %s reaches dtape_stub_unsafe (server abort)\n", __func__), exit(1))
C
for fn in dtape_map_find_shared_entries_locked mach_vm_remap_external_shared; do
    body=$(extract "$fn")
    [[ -n $body ]] || { echo "$fn not found" >&2; exit 2; }
    printf '%s\n' "$body" >>"$work/harness.c"
done
cat >>"$work/harness.c" <<'C'

static kern_return_t remap(vm_map_t map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t source) {
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    *address = 0;
    return mach_vm_remap_external_shared(map, address, size, 0, VM_FLAGS_ANYWHERE, map, source, &cur, &max, 0);
}

int main(void) {
    const uint64_t ps = page_size();
    struct dtape_task task = { NULL };
    dtape_map_t map = { .dtape_task = &task };

    /* Linux places a new mapping directly below the previous one, so in a guest the first remap
       ends where the source begins. Reserve room for that layout: [first remap][source]. */
    char* reserved = mmap(NULL, 4 * ps, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(reserved != MAP_FAILED);
    char* src = mmap(reserved + 2 * ps, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(src == reserved + 2 * ps);
    memset(src, 'a', ps);
    memset(src + ps, 'b', ps);

    /* The first remap shares the whole two-page region (the source becomes shared too). */
    mach_vm_offset_t whole;
    next_anywhere = (uintptr_t)reserved;
    CHECK(remap(&map, &whole, 2 * ps, (uintptr_t)src) == KERN_SUCCESS);
    CHECK(whole + 2 * ps == (uintptr_t)src);
    CHECK(last_inserted->size == 2 * ps);
    CHECK(((char*)whole)[0] == 'a' && ((char*)whole)[ps] == 'b');

    /* Remapping the first page of that region again maps one page of the same object;
       the first remap, which only touches the source, does not overlap it. */
    mach_vm_offset_t first;
    CHECK(remap(&map, &first, ps, (uintptr_t)src) == KERN_SUCCESS);
    CHECK(first != 0 && first != (uintptr_t)src && first != whole);
    CHECK(last_inserted->address == first && last_inserted->size == ps && last_inserted->page_offset == 0);
    CHECK(((char*)first)[0] == 'a' && ((char*)first)[ps - 1] == 'a');

    /* Writes are visible both ways, and through the first remap. */
    ((char*)first)[1] = 'x';
    CHECK(src[1] == 'x' && ((char*)whole)[1] == 'x');
    src[2] = 'y';
    CHECK(((char*)first)[2] == 'y');

    puts("PASS: a shared remap of the first page of a shared region maps one page of the same object");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
