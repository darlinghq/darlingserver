# duct-tape condvar waiters resumed without a signal

`condvar-unsignaled-wakeup.sh` builds `duct-tape/src/condvar.c` on the host, with
stand-ins for the lock types and for the `thread_suspend`/`thread_resume` hooks:

```sh
tests/condvar-unsignaled-wakeup.sh          # working tree
tests/condvar-unsignaled-wakeup.sh <rev>    # condvar.c at <rev>
```

A thread waiting in `dtape_condvar_wait()` can resume without having been signaled,
e.g. when the call it waits in is resumed to handle a signal sent to the thread
(`Thread::_handleInterruptEnterForCurrentThread()`). The test resumes a waiter twice
that way and checks that it is no longer on the wait queue afterwards, that signaling
the queue then wakes no one and ends, and that an ordinary signaled wait still resumes
the waiter once.

Before the fix the waiter stayed queued, and its next wait inserted it again after
itself. The queue then pointed to itself, and the next signal never ended: it kept
resuming the same thread, and the server grew by gigabytes a minute. This happened
when a debugger stopped a process while one of its threads was in `thread_suspend()`
waiting (in `thread_wait()`) for another thread to stop, as WebKit's GPU process does.
