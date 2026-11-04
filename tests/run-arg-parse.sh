#!/bin/bash
# Usage: tests/run-arg-parse.sh [source-root]
#
# Builds tests/host/arg_parse_test.cpp against the real parseNumericArgument() and
# dropTookEffect() cut out of <source-root>/src/darlingserver.cpp, and runs it. No darlingserver
# build is needed. <source-root> defaults to this checkout; pass a checkout or `git archive` of
# another revision to run the same test against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "${1:-$here/..}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$here/host/extract-static.sh" "$root/src/darlingserver.cpp" parseNumericArgument dropTookEffect > "$work/fns.inc"
${CXX:-c++} -std=c++17 -g -O0 -fsanitize="${SANITIZE:-address,undefined}" -fno-sanitize-recover=undefined \
	-DARG_PARSE_INC="\"$work/fns.inc\"" -o "$work/t" "$here/host/arg_parse_test.cpp"
"$work/t"
