#!/bin/bash
# Usage: tests/run-process-maps.sh [source-root]
#
# Builds tests/host/process_maps_test.cpp against the real `/proc/<pid>/maps` helpers cut out of
# <source-root>/src/process.cpp, and runs it. No darlingserver build is needed. <source-root>
# defaults to this checkout; pass a checkout or `git archive` of another revision to run the same
# test against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "${1:-$here/..}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$here/host/extract-static.sh" "$root/src/process.cpp" parseMapsLine procmapQuery procmapProtection > "$work/fns.inc"
${CXX:-c++} -std=c++17 -g -O0 -fsanitize="${SANITIZE:-address,undefined}" -fno-sanitize-recover=undefined \
	-DPROCESS_MAPS_INC="\"$work/fns.inc\"" -o "$work/t" "$here/host/process_maps_test.cpp"
"$work/t"
