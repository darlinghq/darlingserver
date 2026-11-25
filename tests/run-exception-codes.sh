#!/bin/bash
# Usage: tests/run-exception-codes.sh [source-root]
#
# Builds tests/host/exception_codes_test.c against the real dtape_thread_process_signal() and ux_exception()
# cut out of <source-root>/duct-tape/src/thread.c, with the constants taken from the imported XNU headers,
# and runs it. No darlingserver build is needed. <source-root> defaults to this checkout; pass a checkout or
# `git archive` of another revision to run the same test against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "${1:-$here/..}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$here/host/exception-codes-inc.sh" "$root" "$work/fns.inc"

${CC:-cc} -std=gnu11 -g -O0 -Wall -Wno-unused-variable -fsanitize="${SANITIZE:-address,undefined}" -fno-sanitize-recover=undefined \
	-DEXCEPTION_CODES_INC="\"$work/fns.inc\"" -o "$work/t" "$here/host/exception_codes_test.c"
"$work/t"
