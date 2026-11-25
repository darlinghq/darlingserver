#!/bin/bash
# Usage: tests/host/exception-codes-inc.sh <source-root> <out.inc>
#
# Writes the input of tests/host/exception_codes_test.c: the Mach and BSD constants taken from the imported
# XNU headers, the LINUX_* constants of duct-tape/src/thread.c, and the real dtape_thread_process_signal()
# and ux_exception() cut out of duct-tape/src/thread.c.
set -eu
root=$1
out=$2
xnu=$root/duct-tape/xnu
src=$root/duct-tape/src/thread.c

# prints the lines of <file> from the first one matching <start> to the next one matching <end>
cut_out() {
	awk -v s="$2" -v e="$3" '
		!on && $0 ~ s { on = 1 }
		on { print }
		on && $0 ~ e { found = 1; exit }
		END { exit found ? 0 : 1 }
	' "$1" || { echo "exception-codes-inc: $2 not found in $1" >&2; exit 1; }
}

{
	grep -hE '^#define[[:space:]]+(KERN_SUCCESS|KERN_INVALID_ADDRESS|KERN_PROTECTION_FAILURE|KERN_MEMORY_ERROR)[[:space:]]' "$xnu/osfmk/mach/kern_return.h"
	grep -hE '^#define[[:space:]]+EXC_(BAD_ACCESS|BAD_INSTRUCTION|ARITHMETIC|SOFTWARE|BREAKPOINT|SOFT_SIGNAL)[[:space:]]' "$xnu/osfmk/mach/exception_types.h"
	grep -hE '^#define[[:space:]]+EXC_UNIX_[A-Z_]+[[:space:]]' "$xnu/bsd/sys/ux_exception.h"
	grep -hE '^#define[[:space:]]+SIG(ILL|TRAP|ABRT|FPE|KILL|BUS|SEGV|SYS|PIPE)[[:space:]]' "$xnu/bsd/sys/signal.h"
	if [ "$(uname -m)" = aarch64 ]; then
		grep -hE '^#define[[:space:]]+(EXCEPTION_CODE_MAX|EXC_ARM_(DA_ALIGN|UNDEFINED|BREAKPOINT))[[:space:]]' "$xnu/osfmk/mach/arm/exception.h"
	else
		grep -hE '^#define[[:space:]]+(EXCEPTION_CODE_MAX|EXC_I386_(ALIGNFLT|INVOP|BPT|SGL))[[:space:]]' "$xnu/osfmk/mach/i386/exception.h"
	fi
	grep -hE '^#define[[:space:]]+LINUX_[A-Z0-9_]+[[:space:]]' "$src"
	echo
	cut_out "$src" '^void dtape_thread_process_signal[(]' '^};?$'
	echo
	echo int
	cut_out "$src" '^ux_exception[(]' '^}$'
} > "$out"
