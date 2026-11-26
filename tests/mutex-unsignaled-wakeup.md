# duct-tape mutex waiters resumed without being woken

`mutex-unsignaled-wakeup.sh` builds the mutex functions of `duct-tape/src/locks.c`
on the host, with stand-ins for the lock types and for the
`thread_suspend`/`thread_resume` hooks:

```sh
tests/mutex-unsignaled-wakeup.sh          # working tree
tests/mutex-unsignaled-wakeup.sh <rev>    # locks.c at <rev>
```

A thread waiting in `dtape_mutex_lock()` can resume without having been woken by
`dtape_mutex_unlock()`, in the same way as a condvar waiter (see
`condvar-unsignaled-wakeup.md`). The test resumes a waiter twice that way while
another thread owns the mutex, then lets the owner unlock. It checks that the
waiter then owns the mutex, was resumed once, and is no longer on the wait queue,
and that an ordinary contended and an uncontended lock still work.

Before the fix the waiter stayed queued when it was resumed that way, and the
next turn of the wait loop inserted its link again while it was still on the
queue, which corrupts the queue. The test fails on that version because the
waiter is still queued after it has taken the mutex.
