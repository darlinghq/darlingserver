# task_set_exc_guard_behavior and task_set_phys_footprint_limit

`task-setter-stubs.sh` cuts `task_set_phys_footprint_limit()`,
`task_set_exc_guard_behavior()` and `task_get_exc_guard_behavior()` out of
`duct-tape/src/task.c` and builds them on the host against a minimal `struct
task`, with `dtape_stub_unsafe()` replaced by a failure report (in darlingserver
it aborts the server):

```sh
CC="zig cc" tests/task-setter-stubs.sh          # working tree
CC="zig cc" tests/task-setter-stubs.sh <rev>    # task.c at <rev>
```

It checks XNU's results: `task_set_phys_footprint_limit()` returns
`KERN_FAILURE` without touching the old limit (XNU without
`CONFIG_MEMORYSTATUS`); `task_set_exc_guard_behavior()` stores valid bits so the
getter reads them back, rejects bits outside `TASK_EXC_GUARD_ALL` with
`KERN_INVALID_VALUE` (keeping the old value) and a null task with
`KERN_INVALID_TASK` (checked before the value, so a null task with bad bits
still gives `KERN_INVALID_TASK`; a crash on null is reported as a failure).
