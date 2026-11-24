# Thread state buffers of an emulated caller

Run on a Linux host (aarch64 or x86_64) with a C compiler and ASan (`CC`
defaults to `cc`):

```sh
tests/thread-state-caller-architecture.sh          # working tree
tests/thread-state-caller-architecture.sh <rev>    # duct-tape/src/thread.c at <rev>
```

ASan reserves several GB of shadow address space, so the script fails with
errno 12 under `ulimit -v 4000000`. Cap memory with a cgroup instead, or run it
with no limit:

```sh
systemd-run --user --scope -p MemoryMax=2G tests/thread-state-caller-architecture.sh
```

`sigprocess` and `thread_suspended` pass the addresses of a thread state and a
float state buffer in the calling process; the server reads them with
`copyin()` (process_vm_readv) and writes them back with `copyout()`. The buffers
have the layout of the architecture the caller was built for, named in the call
header. Under an emulator that is not the task's architecture: an x86_64
program run by FEX on an arm64 host has an arm64 task, but its handler passes an
`x86_thread_state64_t` (168 bytes) and `x86_float_state64_t` (524 bytes), while
the arm64 layout is 272 and 528 bytes.

The script cuts `dtape_thread_load_state_from_user()`,
`dtape_thread_save_state_to_user()` and their helper out of
`duct-tape/src/thread.c` and builds them under ASan with stand-ins for
`copyin`, `copyout` and the task's saved state. Buffers are exact-size heap
allocations. It checks that a caller of the task's architecture still loads and
saves the state, and, in separate cases, that a load and a save for a caller of
the other architecture each make no copy and leave its sentinel-filled buffers
byte for byte unchanged. Each case prints `CASE: <name>` first, so a failure or
ASan report is attributed to it.

Before the fix (`a31d7b9`) on aarch64, ASan reports a 272-byte read from the
168-byte buffer in the load case. Dropping only the load check fails the load
case the same way; dropping only the save check passes the load case and
reports a 272-byte write in the save case. On an x86_64 host the foreign buffers are the larger arm64
ones, so the old code fails the copy count check instead. Not run under a live
server; the guest signal tests cover that.
