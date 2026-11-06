# mach_vm page queries without page accounting

`vm-page-query-unsupported.sh` cuts `vm_map_page_query_internal()`,
`mach_vm_page_info()`, `mach_vm_page_query()` and `mach_vm_page_range_query()` out of
`duct-tape/src/memory.c` and builds them on the host, with
`dtape_stub_unsafe()` replaced by a failure report (in darlingserver it aborts
the server):

```sh
CC="zig cc" tests/vm-page-query-unsupported.sh          # working tree
CC="zig cc" tests/vm-page-query-unsupported.sh <rev>    # memory.c at <rev>
```

It checks that an unknown `mach_vm_page_info()` flavor, a wrong count or a NULL count gets
`KERN_INVALID_ARGUMENT` (as in XNU's `vm_map_page_range_info_internal()`), that
the valid `VM_PAGE_INFO_BASIC` request and the other queries (including
`vm_map_page_query_internal()`, which the 32-bit `vm32_map_page_query()` calls) get
`KERN_NOT_SUPPORTED` with cleared outputs, and that none of them aborts.
Before the fix the first call reports `reaches dtape_stub_unsafe (server abort)`.

Darling still has no per-page information to return; this only keeps the server
alive and the error codes consistent with XNU.
