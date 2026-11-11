#!/bin/bash
# Usage: tests/run-host.sh <test> [source-root]
#
# Builds tests/host/<test>_test.cpp and runs it. No darlingserver build is needed.
#   message_*  links <source-root>/src/message.cpp, compiled unchanged (real sockets, real MessageQueue).
#   workqueue_*  header-only: includes <source-root>/internal-include/darlingserver/workers.hpp unchanged;
#              SINGLE_THREADED=0 builds it as the multi-threaded queue.
#   logging    links <source-root>/src/logging.cpp, compiled unchanged against stand-in server, process
#              and thread headers (tests/host/logging-stubs).
#   call_*     includes Call::callFromMessage cut verbatim out of <source-root>/src/call.cpp
#              (tests/host/extract-function.py) against stand-in types (tests/host/call_stubs.hpp).
#   system_config  links <source-root>/src/system-config.cpp and duct-tape/src/csr.c, compiled unchanged;
#              <sys/csr.h> comes from the imported XNU headers.
#   process_state  includes closeInheritedFds() and sanitizeProcessState() cut out of
#              <source-root>/src/darlingserver.cpp (tests/host/extract-static.sh).
#   launchd_handshake  includes sendReadyByte() and readReadyByte() cut out of
#              <source-root>/src/darlingserver.cpp (tests/host/extract-static.sh).
#   prefix_setup  links <source-root>/src/prefix-setup.cpp, compiled unchanged, and runs it as the
#              current (unprivileged) user in a private directory.
#   thread_discovery  includes findThreadByStackHint() cut out of <source-root>/src/thread.cpp
#              (tests/host/extract-static.sh) and runs it against the threads of a child process.
#   platform_identity  links <source-root>/src/platform-identity.cpp, compiled unchanged, and the host's libcrypto.
#   code_signing  links <source-root>/src/code-signing.cpp and trust-store.cpp with the parser and runs
#              against tests/fixtures/codesign; also checks what tools/dc-trustcache.py writes.
#   codesign   links <source-root>/src/codesign (the code signature parser), compiled unchanged, the host's
#              libcrypto and libxml2, and runs against tests/fixtures/codesign of this checkout.
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
arg=$work
trap 'rm -rf "$work"' EXIT

flags="-std=c++17 -g -O0 -fsanitize=${SANITIZE:-address,undefined} -fno-sanitize-recover=undefined -I$root/internal-include"
case $test in
	message_*)
		$cxx $flags -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/message.cpp" "$here/host/log_stub.cpp"
		;;
	workqueue_*)
		echo "#define LIBEXEC_PATH \"/usr/local/libexec/darling\"" > "$work/darling-config.h" # config.hpp only needs these two names
		$cxx $flags -I"$work" -pthread -DDSERVER_SINGLE_THREADED=${SINGLE_THREADED:-1} -o "$work/t" "$here/host/${test}_test.cpp"
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
	process_state)
		"$here/host/extract-static.sh" "$root/src/darlingserver.cpp" closeInheritedFds sanitizeProcessState > "$work/process_state.inc"
		$cxx $flags -DPROCESS_STATE_INC="\"$work/process_state.inc\"" -o "$work/t" "$here/host/${test}_test.cpp"
		;;
	launchd_handshake)
		"$here/host/extract-static.sh" "$root/src/darlingserver.cpp" sendReadyByte readReadyByte > "$work/launchd_handshake.inc"
		$cxx $flags -DLAUNCHD_HANDSHAKE_INC="\"$work/launchd_handshake.inc\"" -o "$work/t" "$here/host/${test}_test.cpp"
		;;
	prefix_setup)
		$cxx $flags -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/prefix-setup.cpp"
		;;
	thread_discovery)
		"$here/host/extract-static.sh" "$root/src/thread.cpp" findThreadByStackHint > "$work/thread_discovery.inc"
		$cxx $flags -pthread -DTHREAD_DISCOVERY_INC="\"$work/thread_discovery.inc\"" -o "$work/t" "$here/host/${test}_test.cpp"
		;;
	platform_identity)
		$cxx $flags -I"$root/include" -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/platform-identity.cpp" -lcrypto
		;;
	codesign)
		# -idirafter: only <kern/cs_blobs.h> comes from XNU
		$cc -std=gnu11 -g -O0 -fsanitize=${SANITIZE:-address,undefined} -fno-sanitize-recover=undefined \
			-I"$root/include" -idirafter "$root/duct-tape/xnu/osfmk" $(pkg-config --cflags libxml-2.0) -o "$work/t" \
			"$here/host/${test}_test.c" "$root/src/codesign/dc_codesign.c" "$root/src/codesign/dc_entitlements.c" \
			-lcrypto $(pkg-config --libs libxml-2.0)
		arg=$here/fixtures/codesign
		;;
	code_signing)
		# src/code-signing.cpp and src/trust-store.cpp with the parser and duct-tape/src/csr.c, compiled
		# unchanged; only <kern/cs_blobs.h> and <sys/csr.h> come from XNU. The trust store that
		# tools/dc-trustcache.py writes is checked too when python3 and openssl are there.
		xnu="-I$root/include -I$root/duct-tape/include -idirafter $root/duct-tape/xnu/osfmk -idirafter $root/duct-tape/xnu/bsd"
		san="-fsanitize=${SANITIZE:-address,undefined} -fno-sanitize-recover=undefined"
		$cc -std=gnu11 -g -O0 $san $xnu $(pkg-config --cflags libxml-2.0) -c "$root/src/codesign/dc_codesign.c" -o "$work/dc_codesign.o"
		$cc -std=gnu11 -g -O0 $san $xnu $(pkg-config --cflags libxml-2.0) -c "$root/src/codesign/dc_entitlements.c" -o "$work/dc_entitlements.o"
		$cc -g -O0 $san $xnu -c "$root/duct-tape/src/csr.c" -o "$work/csr.o"
		$cxx $flags $xnu -o "$work/t" "$here/host/${test}_test.cpp" "$root/src/code-signing.cpp" "$root/src/trust-store.cpp" \
			"$work/dc_codesign.o" "$work/dc_entitlements.o" "$work/csr.o" -lcrypto $(pkg-config --libs libxml-2.0)
		mkdir "$work/data"
		set -- "$here/fixtures/codesign" "$work/data"
		if command -v python3 >/dev/null && command -v openssl >/dev/null; then
			tool=$root/tools/dc-trustcache.py
			python3 "$tool" genkey "$work/tool.key" >/dev/null
			python3 "$tool" add "$work/tool-store" 1e010f88a0f10df1da428fb53fad98a1637453ba --key "$work/tool.key" >/dev/null
			python3 "$tool" add "$work/tool-store" c3e41403df5753a157520767cbf90e56d9ffa33f --key "$work/tool.key" >/dev/null
			python3 "$tool" verify "$work/tool-store" --pub "$work/tool.pub" >/dev/null
			set -- "$@" "$work/tool-store" "$work/tool.pub"
		fi
		"$work/t" "$@"
		exit
		;;
	*)
		echo "unknown test: $test" >&2
		exit 2
		;;
esac
"$work/t" "$arg"
