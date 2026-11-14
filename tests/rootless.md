<!-- Copyright (C) 2026 Lubos Dolezel -->

# Run modes and the libexec override

Host-only test, no darlingserver build and no root needed:

```sh
tests/run-host.sh run_mode
tests/run-host.sh prefix_setup
```

`run_mode` compiles the unchanged `src/run-mode.cpp`. It checks how the mode is decided and the rule for
`DARLING_LIBEXEC_PATH`: ignored entirely in Root mode, even when invalid; in the unprivileged modes an
absolute path without control characters, `.` or `..` components.

The mode: in the initial user namespace, and in the launcher's own namespace (a container's, when the
launcher runs inside one), root ids or capabilities make Root and their absence NonRoot. Rootless needs a
namespace other than the parent's that maps only the user and group darlingserver was given, as 0, and
was made by that user, which is what the launcher's rootless child creates. Anything else, including a
namespace that maps a range of ids (LXD/Incus, `systemd-nspawn -U`, rootless Podman, Kubernetes user
namespaces) whose root started the launcher, is Root, which drops to the user's ids. Children of the test
make such namespaces: a single-id one below the test (Rootless), the same with other ids given (Root), a
process sharing a single-id namespace with its parent (Root). Run as root (`sudo` on the built program),
the test also makes namespaces mapping 65536 ids and checks that their root is Root, both below the
parent's namespace and sharing it; as an ordinary user that part is skipped, since writing such a map
needs root or newuidmap.

`prefix_setup` also covers the copy without owners used by the unprivileged modes: set-ID bits are dropped.

Not covered here (needs a built darlingserver and, for NonRoot/Rootless, a Darling install): the whole start-up
in each mode.
