#!/bin/bash
# Usage: tests/run-host.sh <test> [source-root]
#
# Builds tests/host/<test>_test.cpp and runs it. No darlingserver build is needed.
#   message_*  links <source-root>/src/message.cpp, compiled unchanged (real sockets, real MessageQueue).
#   logging    links <source-root>/src/logging.cpp, compiled unchanged against stand-in server, process
#              and thread headers (tests/host/logging-stubs).
#   call_*     includes Call::callFromMessage cut verbatim out of <source-root>/src/call.cpp
#              (tests/host/extract-function.py) against stand-in types (tests/host/call_stubs.hpp).
#   system_config  links <source-root>/src/system-config.cpp and duct-tape/src/csr.c, compiled unchanged;
#              <sys/csr.h> comes from the imported XNU headers.
#   platform_identity  links <source-root>/src/platform-identity.cpp, compiled unchanged, and the host's libcrypto.
# SANITIZE overrides the sanitizer list (ASan needs far more address space than `ulimit -v` allows).
# <source-root> defaults to this checkout; pass a checkout or `git archive` of another revision to
# run the same test against it (that is how a test is shown to fail before its fix).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
test=$1
root=$(cd "${2:-$here/..}" && pwd)
cxx=${CXX:-c++}
cc=${CC:-cc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

flags="-std=c++17 -g -O0 -fsanitize=${SANITIZE:-address,undefined} -fno-sanitize-recover=undefined -I$root/internal-include"
case $test in
	message_*)
		$cxx $flags -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/message.cpp" "$here/host/log_stub.cpp"
		;;
	logging)
		$cxx -I"$here/host/logging-stubs" $flags -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/logging.cpp"
		;;
	call_*)
		python3 "$here/host/extract-function.py" "$root/src/call.cpp" "$work/call.inc"
		$cxx $flags -I"$here/host" -DCALL_FROM_MESSAGE_INC="\"$work/call.inc\"" -o "$work/t" "$here/host/${test}_test.cpp"
		;;
	system_config)
		# -idirafter: only headers the host lacks (sys/csr.h, sys/appleapiopts.h) come from XNU
		xnu="-I$root/include -I$root/duct-tape/include -idirafter $root/duct-tape/xnu/bsd"
		$cc -g -O0 -fsanitize=${SANITIZE:-address,undefined} $xnu -c -o "$work/csr.o" "$root/duct-tape/src/csr.c"
		$cxx $flags $xnu -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/system-config.cpp" "$work/csr.o"
		;;
	platform_identity)
		$cxx $flags -I"$root/include" -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/platform-identity.cpp" -lcrypto
		;;
	*)
		echo "unknown test: $test" >&2
		exit 2
		;;
esac
"$work/t" "$work"
