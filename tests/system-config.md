# System configuration checks

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh system_config   # validation, defaults and the csr-active-config rule
```

`system_config` compiles the unchanged `src/system-config.cpp` and `duct-tape/src/csr.c`; the
`CSR_*` flags come from the imported `duct-tape/xnu/bsd/sys/csr.h`. It checks:

- the built-in defaults (generation 0, no enforcement, `CSR_DISABLE_FLAGS`, no trust store path);
- that complete and empty pushes are accepted and counted;
- that each kind of malformed push (version, size, unknown `present` bits, nonzero generation,
  out-of-range values, values without their `present` bit, a trust store path that is relative,
  empty or not terminated inside its buffer) is rejected with `EINVAL` and changes nothing;
- that the longest path fits and bytes after its NUL are not kept;
- that after the first push `csr_active_config` can lose flags but never gain them (`EPERM`),
  including by leaving the key out, while other values can still change.

Not covered here: the root check, the copy from and to the caller's memory, and
`wait_system_config`, which need a running server. A guest test for those lands in the main tree.
