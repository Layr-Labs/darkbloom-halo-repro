#!/usr/bin/env python3
"""Inspect a built text UKI initrd for the early signed SHA384 autoload path."""

import gzip
import hashlib
import pathlib
import sys


def newc_entries(data: bytes):
    pos = 0
    files = {}
    while True:
        header = data[pos : pos + 110]
        if len(header) != 110 or header[:6] not in (b"070701", b"070702"):
            raise ValueError("malformed newc archive")
        mode = int(header[14:22], 16)
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        if name_size < 1 or name_size > 4096 or size > len(data):
            raise ValueError("invalid newc entry length")
        pos += 110
        name_bytes = data[pos : pos + name_size]
        if len(name_bytes) != name_size or name_bytes[-1:] != b"\0":
            raise ValueError("malformed newc filename")
        name = name_bytes[:-1].decode("utf-8").removeprefix("./")
        pos = (pos + name_size + 3) & ~3
        content = data[pos : pos + size]
        if len(content) != size:
            raise ValueError("truncated newc entry")
        pos = (pos + size + 3) & ~3
        if name == "TRAILER!!!":
            return files, pos
        if name in files:
            raise ValueError(f"duplicate newc entry: {name}")
        files[name] = (mode, content)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-sha384-initrd.py BUILT_INITRD")
    initrd = pathlib.Path(sys.argv[1]).read_bytes()
    if initrd.startswith(b"07070"):
        _, pos = newc_entries(initrd)
        gz = initrd.find(b"\x1f\x8b\x08", pos, pos + 1024)
        if gz < 0 or any(initrd[pos:gz]):
            raise ValueError("early microcode archive not followed by gzip cpio")
    else:
        gz = 0
    if initrd[gz : gz + 3] != b"\x1f\x8b\x08":
        raise ValueError("main initrd is not gzip")
    entries, _ = newc_entries(gzip.decompress(initrd[gz:]))
    helper = pathlib.Path(__file__).with_name("modprobe-sha384").read_bytes()
    modprobe_mode, modprobe = entries["sbin/modprobe"]
    if modprobe_mode & 0o777 != 0o755 or modprobe != helper:
        raise ValueError("early modprobe differs from reviewed helper")
    module_mode, module = entries["lib/modules/sha512.ko"]
    if module_mode & 0o777 != 0o644 or not module.endswith(b"~Module signature appended~\n"):
        raise ValueError("SHA512 module missing signature or expected mode")
    if b"sha512.ko" in entries["etc/nodeos-modules"][1]:
        raise ValueError("SHA512 must load through the early crypto alias")
    print("PASS: early SHA384 helper and signed SHA512 module are in the initrd")
    print("SHA512 module SHA256:", hashlib.sha256(module).hexdigest())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ValueError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
