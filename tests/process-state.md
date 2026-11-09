# darlingserver process state at start

Host-only test, no darlingserver build and no root needed. From the repository root:

```sh
tests/run-host.sh process_state [source-root]
```

It cuts the real `closeInheritedFds()` and `sanitizeProcessState()` out of `src/darlingserver.cpp`
(`tests/host/extract-static.sh`) and runs them in a child process that first sets up what a user
could hand to the setuid launcher: a closed standard input, extra open descriptors (one of them
high), ignored `SIGCHLD` and `SIGTERM`, blocked signals, a umask of 077, a raised core limit and
another working directory. It checks that afterwards the standard descriptors are open, only the
launcher's pipe is kept, signal dispositions and the mask are back to the defaults, no core file can
be written, the umask is 022 with the user's kept for later, and the working directory is `/`.

Only the `close_range()` path runs on kernels that have it; the `/proc/self/fd` fallback is for
kernels before 5.9.
