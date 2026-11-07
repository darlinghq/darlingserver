# Shared remap of the first page of a shared region

`remap-shared-subrange.sh` cuts `mach_vm_remap_external_shared()` and
`dtape_map_find_shared_entries_locked()` out of `duct-tape/src/memory.c` and
builds them on the host. The shared-entry set is replaced by a sorted array, and
the task hooks act on the test process's own memory:

```sh
tests/remap-shared-subrange.sh          # working tree
tests/remap-shared-subrange.sh <rev>    # memory.c at <rev>
```

A first shared (`copy == FALSE`) remap of a two-page region makes the region
shared. A second remap of only its first page must then succeed and map one page
of the same shared object: the new shared entry is one page long at page offset
0, and writes through the new mapping, the source and the first remap are seen
by the others. `mach_vm_remap(3)` does not restrict the source range of a remap
to whole existing regions.

The existing shared entry is reused when it starts at the source address and is
*at least* as long as the request. All shared entries start at memfd offset 0,
so mapping the first `size` bytes of the memfd is right for such a prefix.
Requiring an equal size instead sends this case to `dtape_stub_unsafe()`, which
aborts the server; the script then reports `reaches dtape_stub_unsafe (server
abort)`. If shared entries with a nonzero page offset are ever created, the reuse
condition has to compare offsets as well.

The first remap is placed directly below the source, as Linux places it in a
guest (a new mapping usually goes right below the previous one). That shared
entry ends where the source begins, so it is adjacent to the second remap's
range, not overlapping it. Counting it as overlapping also reaches
`dtape_stub_unsafe()`.
