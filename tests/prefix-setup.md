# Root-mode prefix setup

Host-only test, no darlingserver build and no root needed. From the repository root:

```sh
tests/run-host.sh prefix_setup [source-root]
```

It compiles the unchanged `src/prefix-setup.cpp` and runs it as the current user in a private
temporary directory. It checks:

- which paths may be written into an overlayfs or fuse-overlayfs mount option string: absolute
  paths without ',', ':', '\' or control characters;
- how a prefix path splits into the directory holding it and its name (for `<prefix>.workdir`);
- which prefix, work and private root directories are accepted, by owner and mode;
- the directory mirroring done at prefix creation: missing directories are created with the lower
  mode (a read-only one after its subdirectories), and a symbolic link planted in the upper tree
  where the lower tree has a directory is not followed;
- the copy mode: new, older, newer and same-time files and links, entries of another kind, and
  symbolic links and a hard link planted in the upper tree that lead out of it. Nothing outside
  the upper tree may change, a file with another hard link is not changed, and a set-group-ID bit is
  kept only on a file the copy created itself, never on existing contents with a matching time.
- reading the user's directories from an xdg-user-dirs `user-dirs.dirs` file: `$HOME` expansion,
  absolute paths, escapes, comments, the last line winning, and lines that are not a plain quoted
  value being ignored; and xdg-user-dir's fallback when the file or the entry is missing
  (`$HOME`, `$HOME/Desktop` for the desktop).

The copy and mirror cases fail against the old path-based copy (`copyAndSetAttributes`): it gave
the set-group-ID bit to the user's own file and changed the mode of the hard-linked file outside.

Not covered: the mounts, the descriptor-based mount targets and the id switching, which need root;
and changes made to the upper tree while a walk runs, which a single-threaded test cannot time.
