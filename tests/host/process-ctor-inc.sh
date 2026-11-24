#!/bin/sh
# Usage: process-ctor-inc.sh <source-root> <out.inc>
# Writes the Process(ID, NSID, Architecture, int, bool) constructor verbatim from src/process.cpp.
set -eu
awk '
	/^DarlingServer::Process::Process\(ID id/ { on = 1 }
	on { print }
	on && /^};?$/ { on = 0; found = 1 }
	END { exit found ? 0 : 1 }
' "$1/src/process.cpp" > "$2" || { echo "process-ctor-inc: constructor not found" >&2; exit 1; }
