#!/bin/bash
# Usage: tests/run-pthread-cancel.sh [source-root]
#
# Builds tests/host/pthread_cancel_test.c against the real pthread cancellation functions cut out of
# <source-root>/duct-tape/src/psynch.c and duct-tape/src/thread.c, with the flag values taken from the
# imported XNU headers, and runs it. No darlingserver build is needed. <source-root> defaults to this
# checkout; pass a checkout or `git archive` of another revision to run the same test against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "${1:-$here/..}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$here/host/pthread-cancel-inc.sh" "$root" "$work/defs.inc" "$work/fns.inc"

${CC:-cc} -std=gnu11 -g -O0 -Wall -fsanitize="${SANITIZE:-address,undefined}" -fno-sanitize-recover=undefined \
	-DPTHREAD_CANCEL_DEFS_INC="\"$work/defs.inc\"" -DPTHREAD_CANCEL_FNS_INC="\"$work/fns.inc\"" \
	-o "$work/t" "$here/host/pthread_cancel_test.c"
"$work/t"
