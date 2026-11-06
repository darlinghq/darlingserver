#!/bin/bash
# Usage: tests/run-rpc-reply-fd.sh [source-root]
#
# Runs the real scripts/generate-rpc-wrappers.py of <source-root>, compiles the generated client
# code (rpc.c) against socket-backed hooks (tests/host/rpc_hooks.h) and runs
# tests/host/rpc_reply_fd_test.c against it. No darlingserver build is needed.
# <source-root> defaults to this checkout; pass a checkout or `git archive` of another revision to
# run the same test against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "${1:-$here/..}" && pwd)
work=$(mktemp -d)
# SANITIZE overrides the sanitizer list (ASan needs far more address space than `ulimit -v` allows); empty means none.
san=""
if [ -n "${SANITIZE-address,undefined}" ]; then san="-fsanitize=${SANITIZE-address,undefined} -fno-sanitize-recover=undefined"; fi
trap 'rm -rf "$work"' EXIT

python3 -I "$root/scripts/generate-rpc-wrappers.py" \
	"$work/include/darlingserver/rpc.h" "$work/internal-include/darlingserver/rpc.internal.h" \
	"$work/src/rpc.c" '"rpc_hooks.h"'
${CC:-cc} -std=gnu11 -g -O0 -w $san \
	-I"$work/include" -I"$work/internal-include" -I"$root/include" -I"$here/host" \
	-DRPC_GENERATED_SOURCE="\"$work/src/rpc.c\"" \
	-o "$work/t" "$here/host/rpc_reply_fd_test.c"
"$work/t"
