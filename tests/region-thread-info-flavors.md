# Unknown mach_vm_region and thread_info flavors

`region-thread-info-flavors.sh` cuts the `default:` case of `mach_vm_region()`
(`duct-tape/src/memory.c`) and of `thread_info()` (`duct-tape/src/thread.c`) out
of the source and builds each inside a stand-in switch on the host, with
`dtape_stub_unsafe()` replaced by a failure report (in darlingserver it aborts
the server):

```sh
CC="zig cc" tests/region-thread-info-flavors.sh          # working tree
CC="zig cc" tests/region-thread-info-flavors.sh <rev>    # sources at <rev>
```

It checks that `VM_REGION_TOP_INFO`, `VM_REGION_EXTENDED_INFO` and an arbitrary
value get `KERN_INVALID_ARGUMENT` with `object_name` cleared (and tolerate a
NULL `object_name`), and that `THREAD_EXTENDED_INFO`,
`THREAD_SCHED_TIMESHARE_INFO` and an arbitrary value get `KERN_INVALID_ARGUMENT`.
That is XNU's answer for flavors it does not handle (`vm_map_region()`,
`thread_info_internal()`). The implemented flavors are not exercised.
