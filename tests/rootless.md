<!-- Copyright (C) 2026 Lubos Dolezel -->

# Run modes and the libexec override

Host-only test, no darlingserver build and no root needed:

```sh
tests/run-host.sh run_mode
tests/run-host.sh prefix_setup
```

`run_mode` compiles the unchanged `src/run-mode.cpp`. It checks how the mode is decided (the first line of
`/proc/self/uid_map`, root ids and capabilities), that a process with uid 0 and every capability inside a
user namespace it made itself is Rootless and not Root (a child of the test makes the namespace), and the
rule for `DARLING_LIBEXEC_PATH`: ignored entirely in Root mode, even when invalid; in the unprivileged modes
an absolute path without control characters, `.` or `..` components.

`prefix_setup` also covers the copy without owners used by the unprivileged modes: set-ID bits are dropped.

Not covered here (needs a built darlingserver and, for NonRoot/Rootless, a Darling install): the whole start-up
in each mode.
