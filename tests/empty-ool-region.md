# Empty out-of-line memory region

Run on a Linux host with a C compiler (`CC` defaults to `cc`):

```sh
tests/empty-ool-region.sh
tests/empty-ool-region.sh 9353d34
```

The script cuts the physical-copy accounting block out of
`ipc_kmsg_copyin_body()` in `duct-tape/xnu/osfmk/ipc/ipc_kmsg.c` (working tree,
or the given revision) and builds it with `msg_ool_size_small` derived the way
`ipc_init()` derives it, from the `kalloc_max_prerounded` initializer in
`duct-tape/src/memory.c` (zero in Darling).

Covered cases: a zero-size physical-copy, non-deallocating region is accepted
and needs no space, also after a non-empty region; a one-byte region still
reserves a page; the per-message limit still rejects an oversized region with
`MACH_MSG_VM_KERNEL`; virtual-copy and deallocating regions stay exempt.

At 9353d34 the empty region fails with `MACH_MSG_VM_KERNEL`. This does not run
the rest of `ipc_kmsg_copyin_body()`, `ipc_kmsg_copyin_ool_descriptor()` or a
live server.
