# x86 32-bit debug state forwarding

Run on a Linux host with a C compiler (`CC` defaults to `cc`):

```sh
tests/x86-debug-state32-forward.sh
tests/x86-debug-state32-forward.sh 9353d34
```

The script cuts the real `case x86_DEBUG_STATE32:` block out of
`thread_set_state()` in `duct-tape/src/thread.c` (working tree, or the given
revision) and builds it with a stand-in for the recursive
`thread_set_state()` call. The stand-in checks that it receives flavor
`x86_DEBUG_STATE64`, `x86_DEBUG_STATE64_COUNT`, and the eight registers widened
from the 32-bit state. It also checks that an x86_64 task is still rejected with
`KERN_INVALID_ARGUMENT` without forwarding.

At 9353d34 the block forwards the address of its local pointer, so the stand-in
reads a stack address as `dr0` and the script fails. With the fix it passes.

The x86_DEBUG_STATE64 setter is still a stub returning `KERN_NOT_SUPPORTED`, so
no guest-visible behaviour changes today; this removes a stack over-read. The
64-bit setter will also need to accept the forwarded 32-bit case. Not run under a live server.
