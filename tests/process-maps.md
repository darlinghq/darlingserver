# Memory region lookup checks

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-process-maps.sh   # `/proc/<pid>/maps` lines are parsed correctly
```

The test cuts the `/proc/<pid>/maps` helpers out of `src/process.cpp`
(`tests/host/extract-static.sh`) and runs them against fixed lines (file, shared, anonymous,
`[vsyscall]` and malformed lines) and against every line of the test's own `/proc/self/maps`,
compared with an independent parser. Pass a checkout, or a `git archive` of another revision, to
run the same test against it.

`Process::memoryRegionInfo` and `Process::getNextRegion` themselves need a running server; the guest
benchmark `dserver_rpc_bench.c` (added to the main tree with the darlingserver update) covers them
end to end.
