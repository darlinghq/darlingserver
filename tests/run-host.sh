#!/bin/bash
# Usage: tests/run-host.sh <test> [source-root]
#
# Builds tests/host/<test>_test.cpp and runs it. No darlingserver build is needed.
#   message_*  links <source-root>/src/message.cpp, compiled unchanged (real sockets, real MessageQueue).
#   call_*     includes Call::callFromMessage cut verbatim out of <source-root>/src/call.cpp
#              (tests/host/extract-function.py) against stand-in types (tests/host/call_stubs.hpp).
# SANITIZE overrides the sanitizer list (ASan needs far more address space than `ulimit -v` allows).
# <source-root> defaults to this checkout; pass a checkout or `git archive` of another revision to
# run the same test against it (that is how a test is shown to fail before its fix).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
test=$1
root=$(cd "${2:-$here/..}" && pwd)
cxx=${CXX:-c++}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

flags="-std=c++17 -g -O0 -fsanitize=${SANITIZE:-address,undefined} -fno-sanitize-recover=undefined -I$root/internal-include"
case $test in
	message_*)
		$cxx $flags -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/message.cpp" "$here/host/log_stub.cpp"
		;;
	call_*)
		python3 "$here/host/extract-function.py" "$root/src/call.cpp" "$work/call.inc"
		$cxx $flags -I"$here/host" -DCALL_FROM_MESSAGE_INC="\"$work/call.inc\"" -o "$work/t" "$here/host/${test}_test.cpp"
		;;
	*)
		echo "unknown test: $test" >&2
		exit 2
		;;
esac
"$work/t" "$work"
