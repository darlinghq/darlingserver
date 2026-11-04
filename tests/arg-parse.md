# darlingserver argument parsing and privilege drop

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-arg-parse.sh [source-root]
```

It cuts the real `parseNumericArgument()`, `parseIdArgument()`, `dropIdsMatch()` and `dropTookEffect()` out of `src/darlingserver.cpp`
(`tests/host/extract-static.sh`) and runs them. Pass a checkout, or a `git archive` of another
revision, as `source-root` to run the test against that tree; `SANITIZE=undefined` drops ASan.

Not covered: the `setresuid`/`setresgid` calls themselves and the exit path of `main()`; they need a
setuid launcher and root.
