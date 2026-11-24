#!/bin/sh
set -eu
root=$1
out=$2
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
awk '
	/^static thread_local .*currentThreadVar =/ { on = 1 }
	/^static DarlingServer::Log threadLog/ { on = 0 }
	on { print }
' "$root/src/thread.cpp" > "$out"
awk '/^static thread_local .*interruptedContinuation =/ { print }' "$root/src/thread.cpp" >> "$out"
sh "$here/extract-static.sh" "$root/src/thread.cpp" \
	DarlingServer::Thread::currentThread \
	DarlingServer::Thread::microthreadWorker \
	DarlingServer::Thread::microthreadContinuation \
	DarlingServer::Thread::doWork \
	DarlingServer::Thread::suspend \
	DarlingServer::Thread::setupKernelThread \
	DarlingServer::Thread::syscallReturn \
	DarlingServer::Thread::jumpToResume \
	DarlingServer::Thread::_handleInterruptEnterForCurrentThread >> "$out"
