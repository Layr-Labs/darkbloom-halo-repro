#!/usr/bin/env python3
"""Install a reviewed wizard archive through one local administrator action."""
import argparse
import hashlib
import hmac
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile

MEMBERS = {
    "wizard-admin.py", "wizard-bootstrap.sh", "sealed-wifi.py",
    "sealed-wifi-seal.py", "sealed-wifi-check.py", "collect_quote.py", "setup.py", "setup.desktop",
}
MAX_ARCHIVE = 256 * 1024


def snapshot(archive, checksum, directory):
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Expected a regular archive")
        data = handle.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), checksum):
        raise ValueError("Wizard archive hash mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as bundle:
        entries = bundle.getmembers()
        if len(entries) != len(MEMBERS) or {entry.name for entry in entries} != MEMBERS:
            raise ValueError("Unexpected wizard archive members")
        if any(not entry.isfile() or not 0 < entry.size <= 65536 for entry in entries):
            raise ValueError("Invalid wizard archive member")
        for entry in entries:
            stream = bundle.extractfile(entry)
            if stream is None:
                raise ValueError("Missing wizard archive content")
            with stream, (directory / entry.name).open("xb") as output:
                output.write(stream.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--wifi-interface", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch("[0-9a-f]{64}", args.sha256):
        parser.error("Run as root with the reviewed archive's SHA-256")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir="/var/lib", prefix="darkbloom-wizard-") as staging:
        snapshot(args.archive, args.sha256, Path(staging))
        subprocess.run(
            ["/usr/bin/bash", str(Path(staging) / "wizard-bootstrap.sh"),
             args.owner, args.release, args.wifi_interface],
            check=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


if __name__ == "__main__":
    main()
