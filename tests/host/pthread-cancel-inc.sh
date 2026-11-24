#!/bin/bash
# Usage: tests/host/pthread-cancel-inc.sh <source-root> <defs.inc> <fns.inc>
#
# Writes the inputs of tests/host/pthread_cancel_test.c: the flag values taken from the imported XNU
# headers (<defs.inc>), and the real pthread cancellation and thread abort functions cut out of
# duct-tape/src/psynch.c and duct-tape/src/thread.c (<fns.inc>). <fns.inc> starts with struct dtape_thread,
# built from the real member declarations in duct-tape/internal-include/darlingserver/duct-tape/thread.h that the functions
# use, and the real dtape_thread_for_xnu_thread(), so a member the functions start to use that the header
# lacks (or declares differently) fails here, and a new one is picked up from the header.
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

# prints the declaration of each named member of struct dtape_thread, as written in the header
members() {
	local hdr=$1 name
	shift
	for name in "$@"; do
		awk -v n="$name" '
			/^struct dtape_thread \{/ { on = 1; next }
			on && /^\};?$/ { exit }
			on && $0 ~ "[ \t*]" n ";[ \t]*(//.*)?$" { print; found = 1 }
			END { exit found ? 0 : 1 }
		' "$hdr" || { echo "pthread-cancel-inc: struct dtape_thread has no member $name in $hdr" >&2; exit 1; }
	done
}

xnu=$root/duct-tape/xnu
{
	grep -hE '^#define[[:space:]]+UT_(CANCEL|CANCELED|CANCELDISABLE|NOTCANCELPT|NO_SIGMASK|VFORK)[[:space:]]' "$xnu/bsd/sys/user.h"
	grep -hE '^#define[[:space:]]+(TH_SFLAG_ABORT|TH_SFLAG_ABORTSAFELY|TH_SFLAG_ABORTED_MASK|TH_OPT_INTMASK|TH_WAIT|TH_UNINT)[[:space:]]' "$xnu/osfmk/kern/thread.h"
	grep -hE '^#define[[:space:]]+AST_APC[[:space:]]' "$xnu/osfmk/kern/ast.h"
	grep -hE '^#define[[:space:]]+(THREAD_WAITING|THREAD_INTERRUPTED|THREAD_UNINT|THREAD_INTERRUPTIBLE|THREAD_ABORTSAFE)[[:space:]]' "$xnu/osfmk/kern/kern_types.h"
	grep -hE '^#define[[:space:]]+(KERN_SUCCESS|KERN_FAILURE|KERN_INVALID_ARGUMENT|KERN_NOT_SUPPORTED|KERN_TERMINATED|KERN_NOT_WAITING)[[:space:]]' "$xnu/osfmk/mach/kern_return.h"
} > "$defs"

dthread_h=$root/duct-tape/internal-include/darlingserver/duct-tape/thread.h
{
	echo "typedef struct dtape_thread {"
	members "$dthread_h" uu_flag wakeup_pending interrupt_deferred
	echo "	struct thread xnu_thread;"
	echo "} dtape_thread_t;"
	echo
	extract "$dthread_h" dtape_thread_for_xnu_thread
	extract "$root/duct-tape/src/thread.c" thread_mark_wait_locked thread_abort thread_abort_safely dtape_thread_returning_to_user
	extract "$root/duct-tape/src/psynch.c" dtape_thread_pthread_markcancel dtape_thread_pthread_testcancel dtape_thread_pthread_canceled
} > "$fns"
