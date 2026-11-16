#!/bin/bash
# Usage: tests/run-stub-sweep.sh [git revision]   (DARLING_BUILD: a configured Darling build tree, default ../../../build)
#
# Calls the guest-reachable Mach routines that used to be dtape_stub_unsafe() (a guest MIG call aborted darlingserver
# and with it every process of the prefix) and checks XNU's answers. duct-tape/src/{host,memory,processor,task,thread,
# stubs}.c of the working tree (or of <git revision>) are compiled unchanged with darlingserver's own compile flags
# (from the build tree's compile database) and linked with tests/host/stub_sweep_test.c, which provides
# dtape_stub_log(): a dtape_stub_unsafe() reached there is reported as "ABORT" (the real one never returns).
# current_thread() and task_deallocate() are weakened in the objects so the test can provide them; other unresolved
# symbols are left unresolved (only the routines' early paths run). No darlingserver build is needed.
# Approach after VibeDarling/darlingserver's host tests (tests/vm-page-query-unsupported.sh, tests/run-host.sh).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
build=$(cd "${DARLING_BUILD:-$root/../../../build}" && pwd)
rev=${1:-}
work=$(mktemp -d "${TMPDIR:-/tmp}/stub-sweep.XXXXXX")
trap 'rm -rf "$work"' EXIT

(cd "$build" && ninja -t compdb) > "$work/compdb.json"
# flags of duct-tape/src/processor.c minus the output / dependency options
read -r cc flags < <(python3 -I - "$work/compdb.json" <<'P'
import json, shlex, sys
for e in json.load(open(sys.argv[1])):
    if e["file"].endswith("darlingserver/duct-tape/src/processor.c"):
        a = shlex.split(e["command"]); out = [a[0]]; skip = False
        for x in a[1:]:
            if skip: skip = False; continue
            if x in ("-o", "-MF", "-MT", "-c"): skip = True; continue
            if x == "-MD" or x.endswith("processor.c"): continue
            out.append(x)
        print(" ".join(shlex.quote(x) for x in out)); break
P
)
[ -n "$cc" ] || { echo "no compile command for duct-tape/src/processor.c in $build" >&2; exit 2; }
objs=()
for f in host memory processor task thread stubs; do
	src=$work/$f.c
	if [ -n "$rev" ]; then git -C "$root" show "$rev:duct-tape/src/$f.c" > "$src"; else cp "$root/duct-tape/src/$f.c" "$src"; fi
	# shellcheck disable=SC2086
	eval "$cc $flags -O0 -w -I$root/duct-tape/src -c $src -o $work/$f.o"
	objcopy -W current_thread -W task_deallocate -W dtape_stub_log "$work/$f.o"
	objs+=("$work/$f.o")
done
eval "$cc $flags -O0 -w -c $here/host/stub_sweep_test.c -o $work/test.o"
${CC:-clang} -O0 -w -c "$here/host/stub_sweep_shims.c" -o "$work/shims.o"
${CC:-clang} -no-pie -o "$work/t" "$work/test.o" "$work/shims.o" "${objs[@]}" -Wl,--unresolved-symbols=ignore-all -Wl,--allow-multiple-definition
stdbuf -o0 "$work/t"
