# Incoming message checks

Host-only tests, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh call_pid_order   # pid-mismatched message is rejected before it touches a thread
tests/run-host.sh message_recv     # cut datagrams/records are dropped and their descriptors closed
```

Pass a second argument (a checkout, or a `git archive` of another revision) to run the same test
against that source tree; this is how a test is shown to fail before its fix. `SANITIZE=undefined`
drops ASan (it cannot run under `ulimit -v`).

`message_recv` compiles the unchanged `src/message.cpp` and drives `MessageQueue::receiveMany` over a
real AF_UNIX datagram socket (SO_PASSCRED, as in `Server::start`) and a SOCK_SEQPACKET pair (as in
`kqchan.cpp`), counting `/proc/self/fd`.

`call_pid_order` cuts the real `Call::callFromMessage` out of `src/call.cpp` and runs it against
stand-in `Message`, `Process`, `Thread` and registry types (`tests/host/call_stubs.hpp`). Only the
function body is real.

Not covered: the `try`/`catch` around `callFromMessage` in `Server::start`, which needs the whole
server. End-to-end validation needs a rebuilt server and a started prefix.
