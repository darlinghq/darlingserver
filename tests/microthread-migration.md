# Microthread migration

Run `CXX=clang++ tests/run-host.sh microthread_migration`, or build and run
`darlingserver_microthread_migration` with CTest. The standalone test also works
with `CXX=g++` and `CXX='clang++ -flto -fuse-ld=lld'`.

The test compiles the actual scheduler, suspension, continuation and syscall
return functions from `src/thread.cpp`. The surrounding services are stand-ins;
ucontexts, stacks and both OS threads are real.

Host A suspends one microthread, then stays inside a different microthread.
Host B resumes the first one. Condition variables determine the order without
timing assumptions. The resumed call must retain its identity and return to
host B's scheduler. Continuation captures must survive suspension and be
released after completion, including when suspension replaces the stack or
occurs while handling an interrupt. A supplied lock is released once, including
when its release immediately wakes another host that suspends with a new lock.

Optimization is intentional: caching the original host's TLS base caused the
ARM64 failure. The unmodified implementation fails the identity assertion.
The test runs without sanitizers because it deliberately switches real stacks;
ASan's fiber protocol is a separate build configuration.
