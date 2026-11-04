# Outgoing reply checks

Host-only tests, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh call_push_reply_pipe   # the push_reply synchronization pipe is closed on every exit
tests/run-host.sh message_send           # a reply that fails for its destination only is dropped
```

Pass a second argument (a checkout, or a `git archive` of another revision) to run the same test
against that source tree; this is how a test is shown to fail before its fix. `SANITIZE=undefined`
drops ASan (it cannot run under `ulimit -v`).

`message_send` compiles the unchanged `src/message.cpp` and runs `MessageQueue::sendMany` through the
real `sendmmsg` on AF_UNIX datagram sockets: a peer connected to another socket (EPERM), a removed
reply address (ENOENT), a socket file with no listener (ECONNREFUSED), an empty address on an
unconnected socket (ENOTCONN), a full peer queue (EAGAIN, nothing lost, order kept) and a closed
server socket (EBADF, still fatal). ENOBUFS, ENOMEM and EFAULT cannot be provoked from a test.

`call_push_reply_pipe` cuts the real `Call::callFromMessage` out of `src/call.cpp` and runs it against
stand-in `Message`, `Process`, `Thread` and registry types (`tests/host/call_stubs.hpp`), with a real
pipe standing in for the client's synchronization pipe. Only the function body is real.
