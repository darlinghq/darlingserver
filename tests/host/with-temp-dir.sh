#!/bin/sh
# Usage: tests/host/with-temp-dir.sh <test-program> [args...]
# Runs the program with a new private directory as its last argument (as tests/run-host.sh does)
# and removes the directory afterwards.
dir=$(mktemp -d) || exit 1
"$@" "$dir"
status=$?
rm -rf "$dir"
exit $status
