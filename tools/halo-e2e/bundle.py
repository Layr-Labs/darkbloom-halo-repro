#!/usr/bin/env python3
"""Strict data-only release envelope shared by the signer and root controller."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

DOMAIN = "darkbloom-text-e2e-bundle/v1"
NAMES = frozenset("out/" + n for n in (
    "root.erofs", "root.verity", "models.erofs", "models.verity", "signed.efi",
    "payload.sha256", "signed.efi.sha256", "install-id"))
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
MAX_FILE = 100 * 1024**3


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def parse_manifest(raw):
    if len(raw) > 32768:
        raise ValueError("oversized manifest")
    m = json.loads(raw, object_pairs_hook=no_duplicates)
    if not isinstance(m, dict) or set(m) != {"v", "domain", "sequence", "install_id", "files"}:
        raise ValueError("unexpected manifest schema")
    if type(m["v"]) is not int or m["v"] != 1 or m["domain"] != DOMAIN:
        raise ValueError("unexpected manifest domain/version")
    if type(m["sequence"]) is not int or not 1 <= m["sequence"] <= 2**63-1:
        raise ValueError("invalid sequence")
    if not isinstance(m["install_id"], str) or not ID_RE.fullmatch(m["install_id"]):
        raise ValueError("invalid install ID")
    if not isinstance(m["files"], list) or len(m["files"]) != len(NAMES):
        raise ValueError("unexpected file set")
    names = []
    for row in m["files"]:
        if not isinstance(row, dict) or set(row) != {"name", "size", "sha256"}:
            raise ValueError("invalid file row")
        if not isinstance(row["name"], str) or row["name"] not in NAMES:
            raise ValueError("unapproved filename")
        if type(row["size"]) is not int or not 0 < row["size"] <= MAX_FILE:
            raise ValueError("invalid file size")
        if row["name"] in {"out/install-id", "out/payload.sha256", "out/signed.efi.sha256"} and row["size"] > 4096:
            raise ValueError("oversized metadata file")
        if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise ValueError("invalid file digest")
        names.append(row["name"])
    if names != sorted(NAMES) or raw != canonical(m):
        raise ValueError("noncanonical manifest or duplicate filename")
    return m


def open_dir(path, *, dir_fd=None):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def read_regular(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError("invalid metadata file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            raise ValueError("metadata file changed while reading")
        return data
    finally:
        os.close(fd)


def verify_signature(raw, signature, public_key, private_directory):
    # These verification inputs live in a newly created root-owned directory.
    private_directory = Path(private_directory)
    (private_directory / "manifest.json").write_bytes(raw)
    (private_directory / "manifest.sig").write_bytes(signature)
    subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(public_key),
                    "-signature", str(private_directory / "manifest.sig"),
                    str(private_directory / "manifest.json")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def copy_payload(staging_fd, manifest, destination):
    """Same source FD is streamed, hashed and size checked; never follow links."""
    out_fd = open_dir("out", dir_fd=staging_fd)
    destination = Path(destination)
    (destination / "out").mkdir(mode=0o700)
    try:
        for row in manifest["files"]:
            name = row["name"].split("/")[1]
            src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=out_fd)
            try:
                info = os.fstat(src)
                if not stat.S_ISREG(info.st_mode) or info.st_size != row["size"]:
                    raise ValueError("payload is not a regular file with signed size")
                digest, length = hashlib.sha256(), 0
                target = destination / row["name"]
                with target.open("xb") as output:
                    os.chmod(target, 0o600)
                    while True:
                        chunk = os.read(src, min(4*1024*1024, row["size"] - length + 1))
                        if not chunk:
                            break
                        length += len(chunk)
                        if length > row["size"]:
                            raise ValueError("payload grew while reading")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if length != row["size"] or digest.hexdigest() != row["sha256"]:
                    raise ValueError("payload digest/size mismatch")
            finally:
                os.close(src)
    finally:
        os.close(out_fd)
    if (destination / "out/install-id").read_bytes() != (manifest["install_id"] + "\n").encode():
        raise ValueError("install ID does not match signed manifest")
