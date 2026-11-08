# dtape_task_uidgid

`task-uidgid.sh` cuts `dtape_task_uidgid()` out of `duct-tape/src/task.c` and
builds it on the host against a minimal task with just the audit token and a
lock flag:

```sh
tests/task-uidgid.sh          # working tree
tests/task-uidgid.sh <rev>    # task.c at <rev>
```

The `uidgid` RPC carries ids as signed 32-bit values, with -1 meaning "leave
this id unchanged". The test checks that every other value is stored and read
back, including negative ones: -2 (`nobody`, 4294967294 on macOS) and ids
above `INT32_MAX`. It also checks that the old ids are reported before the
change and that the task lock is released.
