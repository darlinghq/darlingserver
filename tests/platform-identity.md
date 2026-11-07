# Platform identity checks

Host-only test, no darlingserver build needed (it needs the host's OpenSSL 3 libcrypto). From the
repository root:

```sh
tests/run-host.sh platform_identity   # machine ID parsing, derivation, defaults and validation
```

`platform_identity` compiles the unchanged `src/platform-identity.cpp`. It checks:

- that a machine-id(5) file is parsed strictly (32 hex digits, an optional newline, not all zero);
- that the default UUID and serial number match an HMAC-SHA256 computed independently (with
  Python's `hmac` module) for a made-up machine ID, that the UUID is RFC 4122 version 4, and that
  it differs from the machine ID;
- the defaults (MacBookPro16,1 and its board ID on x86, no brand string or memory size, and no
  ROM, MLB serial number, system ID or provisioning UDID), also without a machine ID;
- that complete, empty and partial pushes are accepted and fall back to the defaults for what
  they leave out;
- that the provisioning UDID must equal the platform UUID in effect;
- that each kind of malformed push (version, size, unknown `present` bits, nonzero generation or
  reserved bytes, strings that are empty, unterminated or not printable ASCII, a nil UUID, an
  all-zero system ID or ROM, a zero memory size, values without their `present` bit) is rejected
  with `EINVAL` and changes nothing;
- that the longest string fits and bytes after its NUL are not kept.

Not covered here: the root check, the copy from and to the caller's memory and the `host_info()`
memory size, which need a running server. Guest tests for those land in the main tree.
