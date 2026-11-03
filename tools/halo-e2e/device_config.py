#!/usr/bin/env python3
"""Strict public device pins shared by the root controller and image builder.

The document contains identifiers and paths, never a signing key or a secret.
The root bootstrap copies a validated instance to its fixed protected path.
"""

import json
from pathlib import Path
import re
import sys


KEYS = frozenset({
    "v", "hostname", "owner_user", "host_partuuid", "host_root_uuid",
    "esp_mount", "esp_device", "esp_partuuid", "esp_disk", "esp_partition",
    "factory_efi_dir", "factory_boot_label", "mok_cert_sha256", "wifi_iface",
})
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
DEVICE = re.compile(r"/dev/[A-Za-z0-9._/-]{1,96}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
IFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}\Z")
EFI_DIR = re.compile(r"EFI/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,79}\Z")
BOOT_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,79}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate device config key")
        result[key] = value
    return result


def validate(config):
    if not isinstance(config, dict) or set(config) != KEYS or type(config["v"]) is not int or config["v"] != 1:
        raise ValueError("invalid device config schema")
    patterns = {
        "hostname": NAME,
        "owner_user": USER,
        "host_partuuid": UUID,
        "host_root_uuid": UUID,
        "esp_device": DEVICE,
        "esp_partuuid": UUID,
        "esp_disk": DEVICE,
        "factory_efi_dir": EFI_DIR,
        "factory_boot_label": BOOT_LABEL,
        "mok_cert_sha256": SHA256,
        "wifi_iface": IFACE,
    }
    for key, pattern in patterns.items():
        if type(config[key]) is not str or not pattern.fullmatch(config[key]):
            raise ValueError("invalid device config field: " + key)
    if config["factory_boot_label"] != config["factory_boot_label"].strip():
        raise ValueError("factory boot label has surrounding space")
    if config["esp_mount"] not in ("/efi", "/boot/efi"):
        raise ValueError("unsupported ESP mount path")
    if type(config["esp_partition"]) is not int or not 1 <= config["esp_partition"] <= 128:
        raise ValueError("invalid ESP partition number")
    for key in ("esp_device", "esp_disk"):
        parts = Path(config[key]).parts
        if any(p in (".", "..") for p in parts) or "//" in config[key]:
            raise ValueError("invalid block device path")
    disk = config["esp_disk"]
    suffix = ("p" if disk[-1].isdigit() else "") + str(config["esp_partition"])
    if config["esp_device"] != disk + suffix:
        raise ValueError("ESP device does not match disk and partition")
    return config


def load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("device config must be a small regular file")
    raw = path.read_bytes()
    config = json.loads(raw, object_pairs_hook=_no_duplicates)
    validate(config)
    if raw != canonical(config):
        raise ValueError("noncanonical device config")
    return config


def canonical(config):
    return (json.dumps(validate(config), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def main(argv):
    if len(argv) not in (2, 3) or argv[0] not in ("check", "get") or (argv[0] == "get") != (len(argv) == 3):
        raise ValueError("usage: device_config.py {check PATH|get PATH KEY}")
    config = load(argv[1])
    if argv[0] == "get":
        if argv[2] not in KEYS:
            raise ValueError("unknown device config key")
        print(config[argv[2]])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print("device config: " + str(error), file=sys.stderr)
        raise SystemExit(2)
