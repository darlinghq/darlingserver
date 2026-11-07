# Inline work queue checks

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh workqueue_inline                    # single-threaded queue (the default build)
SINGLE_THREADED=0 tests/run-host.sh workqueue_inline  # multi-threaded queue: tryRunInline refuses
```

`workqueue_inline` includes the unchanged `internal-include/darlingserver/workers.hpp` and checks
`WorkQueue::tryRunInline`: an idle queue runs the item on the calling thread, items queued meanwhile
(a woken thread, another producer) run before it returns and never concurrently with it, and a queue
whose worker is busy refuses.

`message_recv` additionally pins that `receiveMany` treats a short `recvmmsg` batch as a drained socket
and keeps going after a full one.
