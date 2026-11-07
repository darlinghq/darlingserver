#!/usr/bin/env python3
#
# This file is part of Darling.
#
# Copyright (C) 2026 Darling Developers
#
# Darling is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Darling is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Darling.  If not, see <http://www.gnu.org/licenses/>.
#

"""Manage Darling's code signing trust store.

The trust store lists the CDHashes of code that darlingserver treats as platform
binaries. It is Darling's own format (see internal-include/darlingserver/trust-store.hpp),
not Apple's trust cache, and is signed with an Ed25519 key.

darlingserver reads the store from inside the prefix (by default
<prefix>/private/var/db/darling/trustcache) and checks it with the public key
installed at <libexec>/private/var/db/darling/trustcache.pub, which must not be
writable by the user darlingserver runs as. Keep the private key outside the
prefix: whoever can read it can add code to the store.

Needs the openssl command line tool.
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

MAGIC = 0x44544331  # "DTC1"
VERSION = 1
ISSUER = b"darling-local"
ISSUER_LEN = 32
HEADER = struct.Struct("<IIQ32sI")
ENTRY = struct.Struct("<20sI")
SIG_LEN = struct.Struct("<I")
SIGNATURE_SIZE = 64
ENTRY_FLAGS = 1  # not used by darlingserver
MAX_ENTRIES = 1 << 20
OPENSSL_TIMEOUT = 60


def fail(message):
    raise SystemExit(f"dc-trustcache: {message}")


def openssl(args, data=None):
    try:
        return subprocess.run(["openssl"] + args, check=True, capture_output=True,
                              input=data, timeout=OPENSSL_TIMEOUT).stdout
    except FileNotFoundError:
        fail("openssl not found")
    except subprocess.TimeoutExpired:
        fail(f"openssl timed out after {OPENSSL_TIMEOUT} s")
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr.decode(errors="replace").strip() or "openssl failed")


def with_temporary(data, function):
    with tempfile.TemporaryDirectory(prefix="dc-trustcache-") as directory:
        path = Path(directory) / "data"
        path.write_bytes(data)
        return function(path)


def sign(payload, key):
    try:
        signature = with_temporary(payload, lambda message: openssl(
            ["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message)]))
    except RuntimeError as error:
        fail(f"cannot sign: {error}")
    if len(signature) != SIGNATURE_SIZE:
        fail("the key does not make Ed25519 signatures")
    return signature


def verify(payload, signature, pub):
    def check(directory_file):
        signature_file = directory_file.with_name("signature")
        signature_file.write_bytes(signature)
        openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pub),
                 "-in", str(directory_file), "-sigfile", str(signature_file)])
    try:
        with_temporary(payload, check)
        return True
    except RuntimeError:
        return False


def read_store(store, pub):
    """Returns (generation, set of CDHashes), or None if the store does not exist."""
    try:
        data = store.read_bytes()
    except FileNotFoundError:
        return None
    if len(data) < HEADER.size + SIG_LEN.size + SIGNATURE_SIZE:
        fail("the trust store is truncated")
    magic, version, generation, issuer, count = HEADER.unpack_from(data)
    if magic != MAGIC or version != VERSION:
        fail("the trust store has the wrong magic or version")
    if issuer != ISSUER.ljust(ISSUER_LEN, b"\0"):
        fail("the trust store is not issued by darling-local")
    end = HEADER.size + count * ENTRY.size
    if count > MAX_ENTRIES or end + SIG_LEN.size + SIGNATURE_SIZE != len(data):
        fail("the trust store's size does not match its number of entries")
    if SIG_LEN.unpack_from(data, end)[0] != SIGNATURE_SIZE:
        fail("the trust store's signature has the wrong length")
    if not verify(data[:end], data[end + SIG_LEN.size:], pub):
        fail("the trust store's signature does not verify")
    cdhashes = []
    for index in range(count):
        cdhash, _ = ENTRY.unpack_from(data, HEADER.size + index * ENTRY.size)
        if cdhashes and cdhashes[-1] >= cdhash:
            fail("the trust store's entries are not in strictly ascending order")
        cdhashes.append(cdhash)
    return generation, set(cdhashes)


def write_store(store, key, generation, cdhashes):
    if len(cdhashes) > MAX_ENTRIES:
        fail("too many entries")
    table = b"".join(ENTRY.pack(cdhash, ENTRY_FLAGS) for cdhash in sorted(cdhashes))
    payload = HEADER.pack(MAGIC, VERSION, generation, ISSUER.ljust(ISSUER_LEN, b"\0"),
                          len(cdhashes)) + table
    data = payload + SIG_LEN.pack(SIGNATURE_SIZE) + sign(payload, key)
    store.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".dc-trustcache-", dir=store.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, store)
    finally:
        Path(temporary).unlink(missing_ok=True)


def public_key_of(args):
    if args.pub:
        return args.pub
    if args.key:
        return args.key.with_suffix(".pub")
    fail("give --pub (or --key, whose .pub file is used)")


def parse_cdhash(value):
    value = value.replace(":", "").strip()
    try:
        cdhash = bytes.fromhex(value)
    except ValueError:
        cdhash = b""
    if len(cdhash) != 20:
        fail(f"not a CDHash (40 hexadecimal digits): {value}")
    return cdhash


def read_cdhash_file(path):
    cdhashes = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if line:
            try:
                cdhashes.add(parse_cdhash(line.split()[0]))
            except SystemExit as error:
                fail(f"{path}:{number}: {error}")
    return cdhashes


def update(args, change):
    if not args.key:
        fail("give the private key with --key")
    pub = public_key_of(args)
    current = read_store(args.store, pub)
    generation, cdhashes = (0, set()) if current is None else current
    cdhashes = change(set(cdhashes))
    write_store(args.store, args.key, generation + 1, cdhashes)
    print(f"generation={generation + 1} entries={len(cdhashes)}")
    return 0


def command_genkey(args):
    if args.key.exists():
        fail(f"{args.key} already exists")
    args.key.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        openssl(["genpkey", "-algorithm", "ED25519", "-out", str(args.key)])
    except RuntimeError as error:
        fail(f"cannot create the key: {error}")
    finally:
        os.umask(old_umask)
    pub = args.key.with_suffix(".pub")
    try:
        openssl(["pkey", "-in", str(args.key), "-pubout", "-out", str(pub)])
    except RuntimeError as error:
        fail(f"cannot write the public key: {error}")
    os.chmod(pub, 0o644)
    print(f"private key {args.key}, public key {pub}")
    print("install the public key, owned by root, as <libexec>/private/var/db/darling/trustcache.pub")
    return 0


def command_list(args):
    current = read_store(args.store, public_key_of(args))
    if current is None:
        fail(f"no trust store at {args.store}")
    generation, cdhashes = current
    print(f"generation={generation} entries={len(cdhashes)}")
    if args.command == "list":
        for cdhash in sorted(cdhashes):
            print(cdhash.hex())
    return 0


def command_add(args):
    additions = {parse_cdhash(value) for value in args.cdhash}
    if args.source:
        additions |= read_cdhash_file(args.source)
    return update(args, lambda cdhashes: cdhashes | additions)


def command_remove(args):
    removals = {parse_cdhash(value) for value in args.cdhash}
    def change(cdhashes):
        missing = removals - cdhashes
        if missing:
            fail("not in the trust store: " + ", ".join(sorted(cdhash.hex() for cdhash in missing)))
        return cdhashes - removals
    return update(args, change)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    genkey = sub.add_parser("genkey", help="create an Ed25519 key pair (KEY and KEY with .pub)")
    genkey.add_argument("key", type=Path)
    genkey.set_defaults(function=command_genkey)

    for name, function, help_text in (
            ("verify", command_list, "check the store's signature"),
            ("list", command_list, "check the store and list its CDHashes"),
            ("add", command_add, "add CDHashes (creating the store if needed)"),
            ("remove", command_remove, "remove CDHashes")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("store", type=Path, help="the store file (inside the prefix)")
        if name in ("add", "remove"):
            command.add_argument("cdhash", nargs="*", help="40 hexadecimal digits")
            command.add_argument("--key", type=Path, help="the private key")
        if name == "add":
            command.add_argument("--from", dest="source", type=Path, help="a file with one CDHash per line")
        command.add_argument("--pub", type=Path, help="the public key (default: the private key's .pub)")
        if name in ("verify", "list"):
            command.set_defaults(key=None)
        command.set_defaults(function=function)

    args = parser.parse_args(argv)
    return args.function(args)


if __name__ == "__main__":
    sys.exit(main())
