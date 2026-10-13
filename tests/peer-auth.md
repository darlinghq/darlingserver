# Peer authentication checks

Host-only tests, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh call_thread_owner   # a call cannot run on another process's thread
tests/run-host.sh call_peer_uid       # a message from another uid is rejected before any registration
```

Pass a second argument (a checkout, or a `git archive` of another revision) to run the same test
against that source tree; this is how a test is shown to fail before its fix. `SANITIZE=undefined`
drops ASan (it cannot run under `ulimit -v`).

Both tests cut the real `Call::callFromMessage` out of `src/call.cpp` and run it against stand-in
`Message`, `Process`, `Thread` and registry types (`tests/host/call_stubs.hpp`). Only the function body
is real. The uids come from `getuid()`, so the result does not depend on who runs the test.

Not covered: the `chmod(0600)` of the socket in the `Server` constructor and the `dserverdbg` change,
which need a built server and the generated RPC sources. A rejected message is dropped (instead of
ending the server) only with the per-message `catch` in `Server::start`.
