# Log level checks

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh logging   # disabled levels are not formatted and not written
```

`logging` compiles the unchanged `src/logging.cpp` against stand-in server, process and thread
headers (`tests/host/logging-stubs`) and runs with `DSERVER_LOG_LEVEL=info`. It checks
`Log::enabled` for each level, that a debug stream never calls `operator<<` on its values or
`logToStream` on a `Loggable`, and what ends up in `<prefix>/private/var/log/dserver.log`.

Against a tree without `Log::enabled` the test does not compile.
