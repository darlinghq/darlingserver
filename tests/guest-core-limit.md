# Core size limit of the container's processes

Host-only test, no darlingserver build and no root needed. From the repository root:

```sh
tests/run-host.sh guest_core_limit [source-root]
```

On macOS a process starts with a core size limit of 0 under an unlimited hard limit (`launchctl
limit core` prints `0 unlimited` on macOS 26; XNU's initial limits are `DFLCSIZ` 0 and `MAXCSIZ`
`RLIM_INFINITY`), so a crash writes no core file unless the program or its shell raised the limit.
darlingserver used to give launchd, and with it every process of the container, the server's hard
limit as its soft limit. Every crash then wrote a Linux core file, and with a piped `core_pattern`
(systemd-coredump) a process with a large, sparsely used address space cannot finish dying until
the kernel has written all of it, holes included, into the pipe: a crashed WebKit WebContent
process (about 70 GB reserved) took minutes, during which it was neither reported as terminated
nor attachable by a debugger.

The test cuts `guestCoreLimit()` out of `src/darlingserver.cpp` (`tests/host/extract-static.sh`)
and checks that it gives a soft limit of 0 under the server's hard limit; that a child which reserves
64 GiB, touches one page per GiB and then dies of SIGSEGV under it is reaped within 5 seconds (0.07 s
on an Arch Linux host with systemd-coredump; with a piped `core_pattern` the kernel still starts a
dump, but the handler is given the limit of 0 and stores nothing); and that a process can raise the
limit back to the hard limit without privileges (as `ulimit -c unlimited` in a `darling shell` does).
Against the revision before the change the function does not exist and the test does not build.
