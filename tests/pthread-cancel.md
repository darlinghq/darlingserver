# pthread cancellation state

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-pthread-cancel.sh   # markcancel/testcancel/canceled and the safe-abort handling
```

The test cuts `dtape_thread_pthread_markcancel`, `dtape_thread_pthread_testcancel`,
`dtape_thread_pthread_canceled`, `thread_abort_safely`, `thread_mark_wait_locked` and
`dtape_thread_returning_to_user` out of `duct-tape/src` and runs them against a stand-in thread,
with the `UT_*`, `TH_SFLAG_*` and wait constants taken from the imported XNU headers. It checks
xnu's `__pthread_markcancel`/`__pthread_canceled` contract: a mark on a running thread leaves a
one-shot safe abort that only an abort-safe wait consumes, a blocked abort-safe wait is
interrupted, markcancel asks for the thread to be interrupted only when it aborts it (darlingserver
then signals a thread that waits in user space), a second mark does not abort again, a cancel-disabled thread keeps the mark without
being aborted, `canceled(0)` acts on the mark once and then returns `EINVAL`, and testcancel does
not consume the mark. It also checks that a pending safe abort is cleared when the thread's call
replies, so a thread that disables cancellation afterwards sleeps normally. Pass a checkout, or a
`git archive` of another revision, to run the same test against it.

The guest side (cancellation points in libsystem_kernel, darlingserver writing the TSD flag) needs
a running Darling; the guest tests are added to the main tree with the darlingserver update.
