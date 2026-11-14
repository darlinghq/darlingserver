# Code signature parser checks

Host-only tests, no darlingserver build needed (they need the host's OpenSSL 3 or later libcrypto and
libxml2 development files). From the repository root:

```sh
tests/run-host.sh codesign            # fixtures signed on macOS, malformed variants, entitlements
tests/run-fuzz.sh codesign 600        # libFuzzer, ASan+UBSan, 10 minutes (clang only)
tests/run-fuzz.sh entitlements 600
```

`codesign` compiles the unchanged `src/codesign` sources. The `CS_*` constants come from the
imported `duct-tape/xnu/osfmk/kern/cs_blobs.h`. It checks:

- the binaries in `fixtures/codesign` (see the README there) against the values `codesign -dvvv`
  printed for them on macOS 27: identifier, CodeDirectory version and flags, hash type, number of
  special and code slots, page size, runtime version, the CDHash and, for the dual-hash
  signatures, both candidate CodeDirectory digests, that the sha256 CodeDirectory is the one
  chosen, the requirements size, the presence of entitlements, DER entitlements and CMS blobs,
  and that every code page matches;
- both slices of a universal binary, each with its own CDHash, and that the fat table is
  validated (no slices, too many, overlapping each other or the table, running past the file,
  offsets that are not a slice);
- that a changed code page or load command is reported as a page mismatch;
- that each kind of malformed signature is rejected with a reason: truncated, bad magic, a
  SuperBlob larger than the signature, huge blob counts, blob offsets and lengths outside the
  SuperBlob or inside its index, changed requirements, entitlements or DER entitlements (special
  slot mismatch), an entitlements blob hidden behind another slot type, two blobs of one type,
  unknown hash types, hash sizes not matching the type, unsupported page sizes, slot counts not
  matching the code limit, special slots or code slots outside the CodeDirectory, identifiers
  outside it or in its header, a code limit reaching into the signature, unknown versions,
  nonzero `spare2`, two CodeDirectories with one hash type, a signature range outside the file or
  over the load commands, two `LC_CODE_SIGNATURE` commands, load commands past the file, a
  zero-sized load command, byte-swapped headers and files shorter than a magic;
- the entitlements reader: booleans, non-boolean values and absent keys; comments; nested
  dictionaries; trailing NUL padding; and that duplicate keys, `<true>` with content or
  attributes, keys with elements, keys without values, unknown value elements, non-dictionary
  roots, two dictionaries, a missing `<plist>`, malformed XML, entity declarations (including
  nested expansion), empty documents and documents over 1 MiB reject the whole document, while
  an external DTD is not loaded.

The fuzz targets (`tests/fuzz`) treat their input as a file (`codesign`: fat table, each image,
signature, code pages and the embedded entitlements) or as an entitlements plist, and also
check that every pointer the parser returns lies inside the input. They are not registered as
tests.
