#!/bin/sh
# Usage: extract-static.sh <source.cpp> <function-name>...
# Prints each named top-level function verbatim through its closing "};" or "}".
src=$1
shift
for name in "$@"; do
	awk -v n="$name" '
		!on && /^[^[:space:]#]/ && index($0, " " n "(") { on = 1 }
		on { print }
		on && /^};?$/ { on = 0; found = 1 }
		END { exit found ? 0 : 1 }
	' "$src" || { echo "extract-static: $name not found in $src" >&2; exit 1; }
	echo
done
