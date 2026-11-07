# Code signature fixtures

Small arm64 (and one x86_64+arm64) executables built from `hello.c` and signed with Apple's
`codesign` on macOS 27.0.1 (arm64, Xcode clang 21), using the steps in `make-fixtures.sh`
(`cms-dual` was signed in a second run, with a second freshly generated key). They contain only
code compiled from `hello.c`, the linker's start-up stubs and the signatures. No Apple binary is
included.

| file | signature |
|---|---|
| `linker-signed` | the ad-hoc signature `ld` adds by itself (no requirements, no CMS blob) |
| `adhoc` | `codesign -s -` |
| `adhoc-runtime-ent` | ad-hoc, hardened runtime, `ent.plist` entitlements, SHA-1 and SHA-256 CodeDirectories |
| `fat-adhoc` | universal x86_64 + arm64, each slice signed ad-hoc |
| `cms-signed` | a self-signed certificate ("Darling Test Signer") from a temporary keychain |
| `cms-dual` | as `cms-signed`, plus hardened runtime, entitlements and both hash types |
| `unsigned` | `codesign --remove-signature` |

`codesign-dvvv.txt` is the output of `codesign -dvvv`, `codesign -d --entitlements -` and
`codesign --verify --strict -v` for each of them (paths and signing times removed). It is the
oracle for `tests/host/codesign_test.c`.

The self-signed certificate is a throwaway test certificate; its private key was deleted with
the keychain.
