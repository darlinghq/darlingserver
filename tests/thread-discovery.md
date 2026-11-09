# Thread discovery by stack hint

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh thread_discovery   # or: ctest -R darlingserver_thread_discovery
```

The test cuts `findThreadByStackHint()` out of `src/thread.cpp` (`tests/host/extract-static.sh`)
and runs it against a child process with three threads blocked in `pause()`, using real `ptrace`
and `waitpid`. Wrappers can make a register read fail, interrupt a wait with `EINTR`, or make a
thread look as if it exited before it stopped. It checks that the thread whose stack pointer is
nearest below the hint is chosen, that an interrupted wait is retried, that a thread with
unreadable registers is used only when it is the only possible one, that an exited thread is
skipped, and that no thread is left traced. When the child cannot be traced
(`kernel.yama.ptrace_scope` 2 or 3) it prints SKIP.
