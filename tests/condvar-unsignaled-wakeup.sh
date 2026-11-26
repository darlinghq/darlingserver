#!/usr/bin/env bash
# Build duct-tape/src/condvar.c on the host with stand-in hooks and check that a waiter resumed without being
# signaled leaves the wait queue, so that waiting again and signaling afterwards both still work.
# Usage: tests/condvar-unsignaled-wakeup.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/condvar.c")
else
    source=$(cat "$root/duct-tape/src/condvar.c")
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

/* Stand-ins for the types in duct-tape/internal-include/darlingserver/duct-tape/{locks,condvar,thread}.h. */
typedef struct { int held; } libsimple_lock_t;
static void libsimple_lock_init(libsimple_lock_t* l) { l->held = 0; }
static void libsimple_lock_lock(libsimple_lock_t* l) { CHECK(!l->held); l->held = 1; }
static void libsimple_lock_unlock(libsimple_lock_t* l) { CHECK(l->held); l->held = 0; }
typedef struct dtape_mutex_link { TAILQ_ENTRY(dtape_mutex_link) link; } dtape_mutex_link_t;
typedef TAILQ_HEAD(dtape_mutex_head, dtape_mutex_link) dtape_mutex_head_t;
typedef struct { int owned; } dtape_mutex_t;
static void dtape_mutex_lock(dtape_mutex_t* m) { CHECK(!m->owned); m->owned = 1; }
static void dtape_mutex_unlock(dtape_mutex_t* m) { CHECK(m->owned); m->owned = 0; }
typedef struct dtape_condvar { libsimple_lock_t queue_lock; dtape_mutex_head_t queue_head; } dtape_condvar_t;
typedef struct { int dummy; } *thread_t;
typedef struct dtape_thread { dtape_mutex_link_t mutex_link; void* context; } dtape_thread_t;
#define __container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))

static dtape_thread_t waiter = { .context = &waiter };
static thread_t current_thread(void) { return (thread_t)&waiter; }
static dtape_thread_t* dtape_thread_for_xnu_thread(thread_t t) { return (dtape_thread_t*)t; }

static void dtape_condvar_signal(dtape_condvar_t* condvar, size_t count);
static dtape_condvar_t cv;
static int signal_while_suspended;
static int resumes;
/* A suspension drops the given lock; the waiter then either gets signaled or comes back without a signal
 * (as when its call is resumed to handle a signal, see Thread::_handleInterruptEnterForCurrentThread()). */
static void hook_suspend(void* ctx, void* cont, void* cont_ctx, libsimple_lock_t* unlock_me) {
    libsimple_lock_unlock(unlock_me);
    if (signal_while_suspended) dtape_condvar_signal(&cv, 1);
}
static void hook_resume(void* ctx) {
    CHECK(ctx == &waiter);
    /* in the server, every resume schedules the thread again; a signal that never ends is unbounded growth */
    CHECK(++resumes <= 8);
}
static const struct { void (*thread_suspend)(void*, void*, void*, libsimple_lock_t*); void (*thread_resume)(void*); } hooks = { hook_suspend, hook_resume };
static const __typeof__(hooks)* dtape_hooks = &hooks;
C
# condvar.c without its includes (replaced by the stand-ins above), with its functions made static
grep -v '^#include' <<<"$source" | sed -E 's/^void (dtape_condvar_)/static void \1/' >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'

int main(void) {
    dtape_mutex_t m = { 0 };
    dtape_condvar_init(&cv);

    /* resumed twice without being signaled: the waiter must not stay queued */
    dtape_mutex_lock(&m);
    dtape_condvar_wait(&cv, &m);
    CHECK(m.owned);
    CHECK(TAILQ_EMPTY(&cv.queue_head));
    dtape_condvar_wait(&cv, &m);
    CHECK(TAILQ_EMPTY(&cv.queue_head));
    dtape_mutex_unlock(&m);

    /* a signal of the now empty queue wakes no one and ends */
    dtape_condvar_signal(&cv, SIZE_MAX);
    CHECK(resumes == 0);

    /* an ordinary wait still ends with exactly one resume */
    signal_while_suspended = 1;
    dtape_mutex_lock(&m);
    dtape_condvar_wait(&cv, &m);
    dtape_mutex_unlock(&m);
    CHECK(resumes == 1);
    CHECK(TAILQ_EMPTY(&cv.queue_head));
    CHECK(!cv.queue_lock.held);

    printf("PASS\n");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wno-unused-function -o "$work/harness" "$work/harness.c"
"$work/harness"
