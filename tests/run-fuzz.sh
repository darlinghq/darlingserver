#!/bin/bash
# Usage: tests/run-fuzz.sh <codesign|entitlements> [seconds] [corpus-dir]
#
# Builds tests/fuzz/<target>_fuzz.c with the code signature parser (src/codesign, unchanged)
# as a libFuzzer binary under ASan and UBSan, seeds the corpus with tests/fixtures/codesign
# and runs it for the given time (default 60 s). Needs clang with -fsanitize=fuzzer and the
# host's libcrypto and libxml2 development files. The corpus is kept in [corpus-dir] (a
# temporary directory by default); crash inputs are written to the current directory.
# Exits nonzero if the fuzzer found a crash.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
target=$1
seconds=${2:-60}
cc=${CC:-clang}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
corpus=${3:-$work/corpus}
mkdir -p "$corpus"

if ! echo 'int LLVMFuzzerTestOneInput(const char* d, unsigned long s) { return 0; }' | \
	$cc -x c -fsanitize=fuzzer -o "$work/probe" - 2>/dev/null; then
	echo "$cc does not support -fsanitize=fuzzer" >&2
	exit 2
fi

case $target in
	codesign)
		cp "$here/fixtures/codesign/"{linker-signed,adhoc,adhoc-runtime-ent,fat-adhoc,cms-signed,cms-dual,unsigned} "$corpus/"
		;;
	entitlements)
		cp "$here/fixtures/codesign/ent.plist" "$corpus/"
		;;
	*)
		echo "unknown target: $target" >&2
		exit 2
		;;
esac

$cc -std=gnu11 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
	-I"$root/include" -idirafter "$root/duct-tape/xnu/osfmk" $(pkg-config --cflags libxml-2.0) -o "$work/fuzz" \
	"$here/fuzz/${target}_fuzz.c" "$root/src/codesign/dc_codesign.c" "$root/src/codesign/dc_entitlements.c" \
	-lcrypto $(pkg-config --libs libxml-2.0)

"$work/fuzz" -max_total_time="$seconds" -max_len=262144 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 "$corpus"
