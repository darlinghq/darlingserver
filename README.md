# darlingserver

`darlingserver` is Darling's userspace kernel server, much like `wineserver` for Wine.
It implements services that the XNU kernel would normally provide on macOS.

Because of the types of services it provides and the way it implements some of those services, `darlingserver` is very low-level and is a fairly complex system. The documentation explains its architecture and implementation to make it easier to understand and work on.

## Basic Design and Architecture Decisions

### Use Parts of XNU When Possible

The first and most important thing to understand about `darlingserver`'s architecture is that it includes part of the XNU kernel as part of its sources. The reasoning behind this decision can be summed up as *"why reinvent the wheel when you can just use it instead?"*

XNU is open-source and implements many of the services `darlingserver` needs to provide, so we can just use it to implement them. In fact, we've actually already tried reinventing the wheel in the past with an older version of the LKM by implementing those services ourselves. It turned out to be much easier to just duct-tape the necessary XNU code, which was the approach used in the now-defunct LKM.

### Avoid Wasting Resources

This is a conscious design choice that must be kept in mind for all design and implementation decisions. While `darlingserver` strives to avoid wasting resources like file descriptors, CPU time, threads, and memory, among other things:

For example, rather than create a real Linux thread for each thread the server manages, we use userspace threads called microthreads (a.k.a. fibers) and perform cooperative scheduling between them ourselves. Using real Linux threads would greatly simplify thread management within `darlingserver`, but Linux threads are much heavier resource-wise and creating one for each thread the server manages would waste too many resources unnecessarily.

## Architecture and Documentation

Detailed documentation on `darlingserver`'s internals is available in the [Darling Documentation](https://docs.darlinghq.org/internals/darlingserver/index.html):

- [RPC (including S2C calls)](https://docs.darlinghq.org/internals/darlingserver/rpc.html)
- [Threads, processes, and microthreads](https://docs.darlinghq.org/internals/darlingserver/threads-and-friends.html)
- [Duct-taped code](https://docs.darlinghq.org/internals/darlingserver/duct-tape.html)
- [kqueue channels](https://docs.darlinghq.org/internals/darlingserver/kqchannels.html)
- [Interrupt/signal handling](https://docs.darlinghq.org/internals/darlingserver/interrupts.html)
- [Event loop](https://docs.darlinghq.org/internals/darlingserver/event-loop.html)
