# Memory region lookup checks

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-process-maps.sh   # maps lines are parsed correctly; PROCMAP_QUERY agrees with the text
```

The test cuts the `/proc/<pid>/maps` helpers out of `src/process.cpp`
(`tests/host/extract-static.sh`) and runs them against fixed lines (file, shared, anonymous,
`[vsyscall]` and malformed lines) and against every line of the test's own `/proc/self/maps`,
compared with an independent parser. It then runs the PROCMAP_QUERY helpers on its own
`/proc/self/maps` descriptor: a mapping with a hole (covering query, ENOENT in the hole,
covering-or-next query), a shared page, and every region of the text, which must be reported with the
same bounds, offset and protection, and whose end must lead to the next region of the text. Regions
that change while the test runs are skipped. On a kernel without PROCMAP_QUERY (before Linux 6.11)
that part prints SKIP. Pass a checkout, or a `git archive` of another revision, to
run the same test against it.

`Process::memoryRegionInfo` and `Process::getNextRegion` themselves need a running server; the guest
benchmark `dserver_rpc_bench.c` (added to the main tree with the darlingserver update) covers them
end to end.
