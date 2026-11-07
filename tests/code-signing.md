# Code signing state checks

Host-only tests, no darlingserver build needed (they need the host's OpenSSL 3 libcrypto and
libxml2 development files; python3 and the openssl tool for the trust store tool check). From
the repository root:

```sh
tests/run-host.sh code_signing
```

`code_signing` compiles the unchanged `src/code-signing.cpp` and `src/trust-store.cpp` with the
code signature parser. It checks:

- image verification from a file descriptor against `fixtures/codesign` (signed by `codesign` on
  macOS 27): status, signer (ad-hoc or certificate), CDHash, identifier, team ID and the
  `csops(CS_OPS_STATUS)` flags macOS reports for a process started from such a binary, both
  slices of a universal binary, unsigned binaries, and offsets that are not an image;
- the two observed status flag quirks (`quirk_status_flags_omit_adhoc`,
  `quirk_runtime_status_flags`; see `statusFlags` in `src/code-signing.cpp`);
- that a changed code page, a changed CMS signature value, a zeroed CMS blob, a changed
  alternate CodeDirectory that the CMS signature does not cover, a truncated file, an empty
  file, a pipe, a directory and no descriptor all give an invalid image; and that without the
  integrity checks (no policy) a changed code page or CMS value still reports the signature;
- that a signature the parser cannot fully parse (scatter, an unknown CodeDirectory version, an
  unknown blob type, a bad SuperBlob) is reported as validly signed under `off` and `warn`
  (with the problem reported for logging) and as invalid only under `enforce`, while unsigned
  binaries stay unsigned;
- library validation: off without `CS_FORCED_LV`/`CS_REQUIRE_LV` or with the
  `disable-library-validation` entitlement; platform libraries load; the same team
  ID only counts with the same signing key; ad-hoc and unsigned libraries are refused;
- that `cs_update_flags` can only add restrictions and only remove validity or privileges;
- the trust store format: a valid and an empty store, another key, an RSA key, changed entries
  or signature, unsorted or duplicate entries, another issuer, wrong signature length,
  truncated, trailing data, impossible counts; a store written by `tools/dc-trustcache.py`;
- that the store path stays inside the prefix (`..`, relative paths, absolute and relative
  symbolic links, links to host paths) and a missing store is not an error;
- that a public key darlingserver's own user could change is not used.

What needs a running darlingserver (registration once per exec, fork inheritance) is covered by
guest tests.
