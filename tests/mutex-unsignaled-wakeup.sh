#!/usr/bin/env bash
# Build the mutex functions of duct-tape/src/locks.c on the host with stand-in hooks and check that a waiter resumed
# without being woken leaves the wait queue, so that the queue stays intact and an unlock still wakes it once.
# Usage: tests/mutex-unsignaled-wakeup.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/locks.c")
else
    source=$(cat "$root/duct-tape/src/locks.c")
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)

/* Stand-ins for the types in duct-tape/internal-include/darlingserver/duct-tape/{locks,thread}.h. */
typedef struct { int held; } libsimple_lock_t;
static void libsimple_lock_init(libsimple_lock_t* l) { l->held = 0; }
static void libsimple_lock_lock(libsimple_lock_t* l) { CHECK(!l->held); l->held = 1; }
static void libsimple_lock_unlock(libsimple_lock_t* l) { CHECK(l->held); l->held = 0; }
static bool libsimple_lock_try_lock(libsimple_lock_t* l) { if (l->held) return false; l->held = 1; return true; }
typedef struct dtape_mutex_link { TAILQ_ENTRY(dtape_mutex_link) link; } dtape_mutex_link_t;
typedef TAILQ_HEAD(dtape_mutex_head, dtape_mutex_link) dtape_mutex_head_t;
typedef struct dtape_mutex { uintptr_t dtape_owner; libsimple_lock_t dtape_queue_lock; dtape_mutex_head_t dtape_queue_head; } dtape_mutex_t;
typedef struct dtape_thread { dtape_mutex_link_t mutex_link; void* context; } dtape_thread_t;
typedef dtape_thread_t* thread_t;
#define __container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#define TRUE true
#define FALSE false

static dtape_thread_t waiter = { .context = &waiter }, owner = { .context = &owner };
static thread_t current = &waiter;
static thread_t current_thread(void) { return current; }
static dtape_thread_t* dtape_thread_for_xnu_thread(thread_t t) { return t; }
static void panic(const char* message) { fprintf(stderr, "FAIL: panic: %s\n", message); exit(1); }
static void dtape_log_warning(const char* message) { (void)message; }

static void dtape_mutex_unlock(dtape_mutex_t* mutex);
static dtape_mutex_t m;
static int unsignaled_resumes_left;
static int resumes;
/* A suspension drops the given lock. The waiter then either comes back without being woken (as when its call is
 * resumed to handle a signal, see Thread::_handleInterruptEnterForCurrentThread()), or the owner unlocks. */
static void hook_suspend(void* ctx, void* cont, void* cont_ctx, libsimple_lock_t* unlock_me) {
    CHECK(ctx == &waiter);
    libsimple_lock_unlock(unlock_me);
    if (unsignaled_resumes_left > 0) {
        unsignaled_resumes_left--;
        return;
    }
    current = &owner;
    dtape_mutex_unlock(&m);
    current = &waiter;
}
static void hook_resume(void* ctx) {
    CHECK(ctx == &waiter);
    /* in the server, every resume schedules the thread again */
    CHECK(++resumes <= 8);
}
static const struct { void (*thread_suspend)(void*, void*, void*, libsimple_lock_t*); void (*thread_resume)(void*); } hooks = { hook_suspend, hook_resume };
static const __typeof__(hooks)* dtape_hooks = &hooks;
C
# the mutex functions of locks.c (from dtape_mutex_init() to the end of dtape_mutex_unlock()), made static
awk '/^void dtape_mutex_init\(/ { on = 1 } on { print } on && /^};/ && done_unlock { exit } /^void dtape_mutex_unlock\(/ { done_unlock = 1 }' <<<"$source" \
    | sed -E 's/^(void|bool) (dtape_mutex_)/static \1 \2/' >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'

int main(void) {
    dtape_mutex_init(&m);

    /* the owner holds the mutex; the waiter is resumed twice without being woken, then the owner unlocks */
    m.dtape_owner = (uintptr_t)&owner;
    unsignaled_resumes_left = 2;
    dtape_mutex_lock(&m);
    CHECK(m.dtape_owner == (uintptr_t)&waiter);
    CHECK(resumes == 1);
    CHECK(TAILQ_EMPTY(&m.dtape_queue_head));
    CHECK(!m.dtape_queue_lock.held);
    dtape_mutex_unlock(&m);
    CHECK(m.dtape_owner == 0);
    CHECK(resumes == 1);

    /* an ordinary contended lock still ends with exactly one resume */
    m.dtape_owner = (uintptr_t)&owner;
    dtape_mutex_lock(&m);
    CHECK(resumes == 2);
    CHECK(TAILQ_EMPTY(&m.dtape_queue_head));
    dtape_mutex_unlock(&m);

    /* an uncontended lock does not suspend */
    dtape_mutex_lock(&m);
    CHECK(resumes == 2);
    dtape_mutex_unlock(&m);

    printf("PASS\n");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wno-unused-function -o "$work/harness" "$work/harness.c"
"$work/harness"
