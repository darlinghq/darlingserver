#!/usr/bin/env bash
# Build the real dtape_task_uidgid() from duct-tape/src/task.c on the host and
# check that only -1 means "unchanged": other ids, including negative ones such
# as -2 (nobody), are stored and read back.
# Usage: tests/task-uidgid.sh [git revision]
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ge 1 ]]; then
    source=$(git -C "$root" show "$1:duct-tape/src/task.c")
else
    source=$(cat "$root/duct-tape/src/task.c")
fi
body=$(awk '/^void dtape_task_uidgid\(/ { grab = 1 } grab { print } grab && /^};?$/ { exit }' <<<"$source")
[[ -n $body ]] || { echo "dtape_task_uidgid not found" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/harness.c" <<'C'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (line %d)\n", #c, __LINE__); exit(1); } } while (0)
/* Only the fields dtape_task_uidgid() touches; val[1] is the uid, val[2] the gid. */
typedef struct { unsigned int val[8]; } audit_token_t;
struct task { audit_token_t audit_token; int locked; };
typedef struct dtape_task { struct task xnu_task; } dtape_task_t;
static void task_lock(struct task* t) { CHECK(!t->locked); t->locked = 1; }
static void task_unlock(struct task* t) { CHECK(t->locked); t->locked = 0; }
C
printf '%s\n' "$body" >>"$work/harness.c"
cat >>"$work/harness.c" <<'C'

static void expect(dtape_task_t* task, uid_t uid, gid_t gid) {
    int old_uid = 0, old_gid = 0;
    dtape_task_uidgid(task, -1, -1, &old_uid, &old_gid);
    CHECK((uid_t)old_uid == uid);
    CHECK((gid_t)old_gid == gid);
    CHECK(!task->xnu_task.locked);
}

int main(void) {
    dtape_task_t task = { 0 };
    const uid_t nobody = (uid_t)-2;

    task.xnu_task.audit_token.val[1] = 501;
    task.xnu_task.audit_token.val[2] = 20;
    expect(&task, 501, 20);

    /* The reply carries the ids from before the change. */
    int old_uid = 0, old_gid = 0;
    dtape_task_uidgid(&task, 0, 0, &old_uid, &old_gid);
    CHECK(old_uid == 501 && old_gid == 20);
    expect(&task, 0, 0);

    /* -2 (nobody) is an id like any other. */
    dtape_task_uidgid(&task, -1, (int)nobody, NULL, NULL);
    expect(&task, 0, nobody);
    dtape_task_uidgid(&task, (int)nobody, -1, NULL, NULL);
    expect(&task, nobody, nobody);

    /* Large ids above INT32_MAX also come through as negative values. */
    dtape_task_uidgid(&task, (int)(uid_t)0x80000000u, (int)(gid_t)0xfffffff0u, NULL, NULL);
    expect(&task, 0x80000000u, 0xfffffff0u);

    /* -1 alone leaves each id as it is. */
    dtape_task_uidgid(&task, 0, -1, NULL, NULL);
    expect(&task, 0, 0xfffffff0u);
    dtape_task_uidgid(&task, -1, 20, NULL, NULL);
    expect(&task, 0, 20);

    puts("PASS: dtape_task_uidgid treats only -1 as unchanged");
    return 0;
}
C
${CC:-cc} -std=gnu11 -Wall -Wextra -O2 "$work/harness.c" -o "$work/harness"
"$work/harness"
