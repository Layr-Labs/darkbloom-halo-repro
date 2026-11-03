#!/usr/bin/env python3
"""Stage public, per-machine pins for a separately SHA-256-pinned bootstrap archive."""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_config import canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True, help="new archive staging root")
    parser.add_argument("--boot-cert", type=Path, required=True, help="enrolled public DER certificate")
    for key in ("hostname", "owner_user", "host_partuuid", "host_root_uuid", "esp_mount",
                "esp_device", "esp_partuuid", "esp_disk", "factory_efi_dir", "factory_boot_label", "wifi_iface"):
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    parser.add_argument("--esp-partition", type=int, required=True)
    args = parser.parse_args()
    if args.boot_cert.is_symlink() or not args.boot_cert.is_file():
        parser.error("boot certificate must be a regular file")
    cert = args.boot_cert.read_bytes()
    if not 0 < len(cert) <= 65536:
        parser.error("boot certificate size is invalid")
    subprocess.run(["openssl", "x509", "-inform", "DER", "-noout"], input=cert,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    values = {key: getattr(args, key) for key in ("hostname", "owner_user", "host_partuuid",
              "host_root_uuid", "esp_mount", "esp_device", "esp_partuuid", "esp_disk",
              "esp_partition", "factory_efi_dir", "factory_boot_label", "wifi_iface")}
    config = canonical({"v": 1, **values, "mok_cert_sha256": hashlib.sha256(cert).hexdigest()})
    inputs = args.out_dir / "inputs"
    if args.out_dir.is_symlink() or (args.out_dir.exists() and not args.out_dir.is_dir()) or inputs.exists() or inputs.is_symlink():
        parser.error("output inputs directory already exists or is unsafe")
    inputs.mkdir(parents=True, mode=0o700)
    for name, data in (("device.json", config), ("boot-cert.der", cert)):
        fd = os.open(inputs / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    print("Staged public device pins and public boot certificate under inputs/.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("device config: " + str(error), file=sys.stderr)
        raise SystemExit(2)
