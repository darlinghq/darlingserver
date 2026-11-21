# IOSurface service registry

Host-only test, no darlingserver build needed. From the repository root:

```sh
tests/run-host.sh iosurface_registry
```

`iosurface_registry` compiles the unchanged `src/iosurface.cpp` and drives `IOSurfaceRegistry` with
made-up process IDs and real memory files. It checks:

- that every new memory object gets a new nonzero ID, and that the same object (also through a
  duplicate descriptor) is the same surface, whatever ID hint comes with it;
- that bad arguments are refused (no descriptor, a pipe, unknown flags, a counter that is
  misaligned or outside the first page);
- that a surface that is not global is found by ID only by the processes that hold it, and a
  global one by any process, and that the lookup returns the memory object;
- that only holders publish or copy the GPU buffer, that its description is validated (render
  node present and terminated), that the first buffer published is kept and handed to a racing
  publisher, and that publishing counts the publisher as importing it;
- the number of memory users written into the memory object at the counter offset as holders
  come, import the buffer, say they use the memory, and go;
- that holds are counted per process, and that a process that exits drops all of them, freeing
  surfaces it alone held;
- that a surface whose holders all left comes back under its old ID when that is free, and under
  a new one otherwise;
- that no descriptor is left open once every surface is gone.

Not covered here: the calls themselves (finding the calling process, copying the description to
and from its memory, passing descriptors), and dropping holds at exit and exec, which need a
running server. The guest test `iosurface_cross_process_gpu` in the main tree covers those.
