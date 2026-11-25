#!/usr/bin/env python3
"""Package the fixed Halo wizard bootstrap files for independent review."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import stat
import tarfile


ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "tools/halo-e2e/wizard-admin.py",
    "tools/halo-e2e/wizard-bootstrap.sh",
    "tools/halo-e2e/sealed-wifi.py",
    "tools/halo-e2e/sealed-wifi-seal.py",
    "tools/halo-e2e/sealed-wifi-check.py",
    "tools/tpm/collect_quote.py",
    "tools/halo-e2e/setup.py",
    "tools/halo-e2e/setup.desktop",
)


def build(output):
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in SOURCES:
            source = ROOT / name
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError("Expected a regular bootstrap file: " + name)
                data = handle.read(65537)
            if not 0 < len(data) <= 65536:
                raise ValueError("Unexpected bootstrap file size: " + name)
            item = tarfile.TarInfo(source.name)
            item.size = len(data)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(data))
    data = archive_bytes.getvalue()
    if len(data) > 256 * 1024:
        raise ValueError("Wizard archive exceeds its byte limit")
    with output.open("xb") as handle:
        handle.write(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        build(args.out)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
