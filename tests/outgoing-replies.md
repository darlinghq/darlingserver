# Outgoing reply checks

Host-only tests, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh call_push_reply_pipe   # the push_reply synchronization pipe is closed on every exit
tests/run-host.sh message_send           # a reply that fails for its destination only is dropped
tests/run-host.sh message_credentials    # cached sender credentials are correct, also after fork()
tests/run-host.sh message_direct_send    # replies are sent by the producing thread, in order
```

The same tests also run under `ctest` in the build directory (`darlingserver_<test>`), without
sanitizers.

Pass a second argument (a checkout, or a `git archive` of another revision) to run the same test
against that source tree; this is how a test is shown to fail before its fix. `SANITIZE=undefined`
drops ASan (it cannot run under `ulimit -v`).

`message_send` compiles the unchanged `src/message.cpp` and runs `MessageQueue::sendMany` through the
real `sendmmsg` on AF_UNIX datagram sockets: a peer connected to another socket (EPERM), a removed
reply address (ENOENT), a socket file with no listener (ECONNREFUSED), an empty address on an
unconnected socket (ENOTCONN), a full peer queue (EAGAIN, nothing lost, order kept) and a closed
server socket (EBADF, still fatal). ENOBUFS, ENOMEM and EFAULT cannot be provoked from a test.

`message_direct_send` compiles the unchanged `src/message.cpp` and runs `MessageQueue::pushAndSend`
(what `Server::sendMessage` uses) on AF_UNIX datagram sockets. The owner is notified only when messages
are left queued: when the socket is full, or when sending fails with an error (which is then thrown).
A direct send never overtakes queued messages, also with 4 threads sending at once while the test
retries like the main loop (`SANITIZE=thread` checks the locking). Descriptors are closed on the
sending side once sent, and dead peers (ENOENT, ECONNREFUSED) are dropped without an error.
`Server::sendMessage` itself and the main loop's retry need the whole server and are not covered.

`call_push_reply_pipe` cuts the real `Call::callFromMessage` out of `src/call.cpp` and runs it against
stand-in `Message`, `Process`, `Thread` and registry types (`tests/host/call_stubs.hpp`), with a real
pipe standing in for the client's synchronization pipe. Only the function body is real.

`message_credentials` compiles the unchanged `src/message.cpp` and sends `Message`s over an
SO_PASSCRED socket pair, before and after `Message::initializeServerCredentials()`, and from a forked
child (the kernel rejects a message whose PID is not the sender's, so a stale cached PID fails).
