# Root-mode prefix setup

Host-only test, no darlingserver build and no root needed. From the repository root:

```sh
tests/run-host.sh prefix_setup [source-root]
```

It compiles the unchanged `src/prefix-setup.cpp` and runs it as the current user in a private
temporary directory. It checks:

- which paths may be written into an overlayfs or fuse-overlayfs mount option string: absolute
  paths without ',', ':', '\' or control characters.

Not covered: the mounts themselves, which need root.
