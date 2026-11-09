# Prefix cleanup at container start

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh prefix_preinit   # or: ctest -R darlingserver_prefix_preinit
```

The test cuts `wipeDir()` and `darlingPreInit()` out of `src/darlingserver.cpp`
(`tests/host/extract-static.sh`) and runs them twice on two prefixes in a private directory, one
with a plain `var` and one where `var` is a symbolic link to `private/var`. Files in `/var/tmp`
must survive both starts unchanged (on macOS `/var/tmp` persists across restarts; only `/tmp` is
cleaned), `/var/run` must be empty afterwards, and a symbolic link in `/var/run` that points out of
the prefix must be removed without touching its target. Run it against a checkout before the
change (with `darlingPreInit` made static) and the `/var/tmp` checks fail.
