#!/usr/bin/env python3
"""Package only reviewed root helper code and public device pins; never signs."""

import argparse
import hashlib
import io
from pathlib import Path
import stat
import tarfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_config import load


ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "tools/halo-e2e/bootstrap.sh",
    "tools/halo-e2e/control.py",
    "tools/halo-e2e/bundle.py",
    "tools/halo-e2e/device_config.py",
    "tools/halo-e2e/check-mok.py",
    "tools/tpm/read_ek_chain.py",
    "tools/tpm/collect_quote.py",
    "nodeos/text/install.sh",
)
INPUTS = ("inputs/device.json", "inputs/boot-cert.der")


def regular(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError("unexpected bootstrap source file: " + str(path))
    return path.read_bytes()


def build(inputs, output):
    if inputs.is_symlink() or not inputs.is_dir() or {p.name for p in inputs.iterdir()} != {"device.json", "boot-cert.der"}:
        raise ValueError("inputs must contain only device.json and boot-cert.der")
    config = load(inputs / "device.json")
    cert = regular(inputs / "boot-cert.der", 65536)
    if hashlib.sha256(cert).hexdigest() != config["mok_cert_sha256"]:
        raise ValueError("public certificate differs from device pin")
    if output.exists() or output.is_symlink():
        raise ValueError("bootstrap archive already exists")
    with output.open("xb") as sink:
        with tarfile.open(fileobj=sink, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in (*SOURCES, *INPUTS):
                data = regular(ROOT / name if name in SOURCES else inputs / Path(name).name,
                               2 * 1024 * 1024 if name in SOURCES else 65536)
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o755 if name in {"tools/halo-e2e/bootstrap.sh", "nodeos/text/install.sh"} else 0o600
                item.uid = item.gid = item.mtime = 0
                archive.addfile(item, io.BytesIO(data))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"{digest}  {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.inputs, args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
