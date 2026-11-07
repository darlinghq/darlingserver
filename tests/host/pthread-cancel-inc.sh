#!/bin/bash
# Usage: tests/host/pthread-cancel-inc.sh <source-root> <defs.inc> <fns.inc>
#
# Writes the inputs of tests/host/pthread_cancel_test.c: the flag values taken from the imported XNU
# headers (<defs.inc>), and the real pthread cancellation functions cut out of duct-tape/src/psynch.c
# and duct-tape/src/thread.c (<fns.inc>).
set -eu
root=$1
defs=$2
fns=$3

# prints each named top-level function definition verbatim, up to its closing "};" or "}"
extract() {
	local src=$1 name
	shift
	for name in "$@"; do
		awk -v n="$name" '
			!on && /^[A-Za-z_]/ && index($0, " " n "(") && !/;$/ { on = 1 }
			on { print }
			on && /^};?$/ { on = 0; found = 1 }
			END { exit found ? 0 : 1 }
		' "$src" || { echo "pthread-cancel-inc: $name not found in $src" >&2; exit 1; }
		echo
	done
}

xnu=$root/duct-tape/xnu
{
	grep -hE '^#define[[:space:]]+UT_(CANCEL|CANCELED|CANCELDISABLE|NOTCANCELPT|NO_SIGMASK|VFORK)[[:space:]]' "$xnu/bsd/sys/user.h"
	grep -hE '^#define[[:space:]]+(TH_SFLAG_ABORT|TH_SFLAG_ABORTSAFELY|TH_SFLAG_ABORTED_MASK|TH_OPT_INTMASK|TH_WAIT)[[:space:]]' "$xnu/osfmk/kern/thread.h"
	grep -hE '^#define[[:space:]]+(THREAD_WAITING|THREAD_INTERRUPTED|THREAD_UNINT|THREAD_INTERRUPTIBLE|THREAD_ABORTSAFE)[[:space:]]' "$xnu/osfmk/kern/kern_types.h"
	grep -hE '^#define[[:space:]]+(KERN_SUCCESS|KERN_NOT_WAITING)[[:space:]]' "$xnu/osfmk/mach/kern_return.h"
} > "$defs"

{
	extract "$root/duct-tape/src/thread.c" thread_mark_wait_locked thread_abort_safely dtape_thread_returning_to_user
	extract "$root/duct-tape/src/psynch.c" dtape_thread_pthread_markcancel dtape_thread_pthread_testcancel dtape_thread_pthread_canceled
} > "$fns"
