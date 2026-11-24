#!/usr/bin/python3
"""Verify one catalog selection per boot; never execute owner-supplied code."""
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

CONFIG = Path("/usr/share/darkbloom/model-catalog.json")
PUBLIC_KEY = Path("/usr/share/darkbloom/model-package.pub.pem")
VERIFIER = "/usr/lib/darkbloom/model-package.py"
RUNTIME = Path("/run/darkbloom-model")
MODELS = Path("/usr/share/darkbloom/models")
MAPPER = "/dev/mapper/nodeos-catalog-model"
MAPPING_NAME = "nodeos-catalog-model"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root", "DM_DISABLE_UDEV": "1"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate catalog policy field")
        value[key] = item
    return value


def policy(raw, cmdline):
    modes = [word[len("nodeos.model-mode="):] for word in cmdline.split() if word.startswith("nodeos.model-mode=")]
    if modes != ["catalog"] or not 0 < len(raw) <= 4096:
        raise ValueError("Catalog policy requires the signed catalog boot mode")
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    if (not isinstance(value, dict) or set(value) != {"v", "library", "engine_version", "workflow_sha256"}
            or type(value["v"]) is not int or value["v"] != 1
            or not isinstance(value["library"], str)
            or not re.fullmatch(r"/run/nodeos/host/home/[a-z_][a-z0-9_-]{0,31}/\.local/share/darkbloom/models", value["library"])
            or not isinstance(value["engine_version"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:+_-]{0,79}", value["engine_version"])
            or not isinstance(value["workflow_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["workflow_sha256"])):
        raise ValueError("Invalid measured catalog policy")
    return value


def matches_policy(manifest, expected):
    if (manifest["engine_version"] != expected["engine_version"]
            or manifest["workflow_sha256"] != expected["workflow_sha256"]):
        raise ValueError("Selected model does not match the measured engine/workflow policy")


def write_new(name, data, mode):
    descriptor = os.open(RUNTIME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    except BaseException:
        (RUNTIME / name).unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def command(args, *, pass_fds=()):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env=ENV, pass_fds=pass_fds, timeout=120)


def mapper_identity():
    info = os.stat(MAPPER)
    if not stat.S_ISBLK(info.st_mode):
        raise ValueError("Catalog mapper is not a block device")
    entry = Path(f"/sys/dev/block/{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}")
    if (entry / "dm/name").read_text().strip() != MAPPING_NAME:
        raise ValueError("Catalog mapper name differs")
    node = entry.resolve(strict=True).name
    if not re.fullmatch(r"dm-[0-9]+", node):
        raise ValueError("Unexpected catalog mapper identity")
    target = "/dev/" + node
    actual = os.stat(target)
    if not stat.S_ISBLK(actual.st_mode) or actual.st_rdev != info.st_rdev:
        raise ValueError("Catalog mapper device differs")
    return info, target


def open_mapping(expected, api):
    if Path(MAPPER).exists() or Path(MAPPER).is_symlink() or any(RUNTIME.iterdir()):
        raise ValueError("Catalog mapping or runtime state already exists")
    attempted = False
    try:
        with api["open_package"](Path(expected["library"]), PUBLIC_KEY, snapshot_tree=True) as package:
            matches_policy(package.manifest, expected)
            # The verifier makes one sealed, authenticated memfd snapshot of
            # the tree. Its header cannot be changed by the owner before parse.
            # The original image FD stays held through loop/dm setup; dm-verity
            # authenticates its data before EROFS or llama can parse a block.
            attempted = True
            command(["/usr/sbin/veritysetup", "open", f"/proc/self/fd/{package.image_fd}",
                     MAPPING_NAME, f"/proc/self/fd/{package.tree_fd}", package.manifest["verity_root"]],
                    pass_fds=(package.image_fd, package.tree_fd))
            _info, target = mapper_identity()
            # The fixed root-controlled alias avoids systemd waiting for a
            # udev .device unit. A real block node under /run would be nodev.
            os.symlink(target, RUNTIME / "mapper")
            write_new("manifest.pending", package.manifest_raw, 0o600)
    except BaseException:
        if attempted and Path(MAPPER).exists():
            try:
                command(["/usr/sbin/veritysetup", "close", MAPPING_NAME])
            except (OSError, subprocess.SubprocessError):
                pass
        raise


def check_mount():
    info, target = mapper_identity()
    alias = RUNTIME / "mapper"
    if not alias.is_symlink() or os.readlink(alias) != target or os.stat(alias).st_rdev != info.st_rdev:
        raise ValueError("Catalog mapper handoff differs")
    if os.stat(MODELS).st_dev != info.st_rdev:
        raise ValueError("Model path is not the authenticated mapper")
    identity = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        if separator and len(fields) >= 6 and fields[4] == str(MODELS):
            if (fields[2] != identity or after.split()[0] != "erofs"
                    or not {"ro", "nodev", "nosuid", "noexec"} <= set(fields[5].split(","))):
                raise ValueError("Model mount lacks the required isolation options")
            return
    raise ValueError("Authenticated model mount is absent")


def check_weights(manifest):
    directory = os.open(MODELS, DIR_FLAGS)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) & 0o005 != 0o005:
            raise ValueError("Model directory is not readable by the engine")
        child = os.open("text", DIR_FLAGS, dir_fd=directory)
        os.close(directory)
        directory = child
        if stat.S_IMODE(os.fstat(directory).st_mode) & 0o005 != 0o005:
            raise ValueError("Model directory is not readable by the engine")
        descriptor = os.open("model.gguf", FILE_FLAGS, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_size != manifest["model_size"]
                    or not stat.S_IMODE(info.st_mode) & 0o004):
                raise ValueError("Mounted GGUF differs from signed size or cannot be read by the engine")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def ready(expected, api):
    if any((RUNTIME / name).exists() or (RUNTIME / name).is_symlink() for name in ("manifest.json", "model.env")):
        raise ValueError("Catalog runtime settings already exist")
    descriptor = os.open(RUNTIME / "manifest.pending", FILE_FLAGS)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= 4096:
            raise ValueError("Catalog handoff is not root-controlled")
        raw = os.read(descriptor, 4097)
        if len(raw) != info.st_size:
            raise ValueError("Catalog handoff changed")
    finally:
        os.close(descriptor)
    manifest = api["validate_manifest"](raw)
    matches_policy(manifest, expected)
    check_mount()
    check_weights(manifest)
    # Rust Llama::connect hashes every mounted GGUF byte against this digest
    # before reporting the model or obtaining a lease. Avoid a second full scan.
    environment = f'DB_TEXT_MODEL_ID={manifest["model_id"]}\nDB_TEXT_MODEL_SHA256={manifest["model_sha256"]}\n'.encode("ascii")
    created = []
    try:
        write_new("manifest.json", raw, 0o640)
        created.append("manifest.json")
        write_new("model.env", environment, 0o640)
        created.append("model.env")
    except BaseException:
        for name in created:
            (RUNTIME / name).unlink(missing_ok=True)
        raise


def main():
    os.umask(0o027)
    if os.geteuid() != 0 or sys.argv[1:] not in (["open"], ["ready"]):
        raise ValueError("Fixed root catalog operation required")
    expected = policy(CONFIG.read_bytes(), Path("/proc/cmdline").read_text())
    api = runpy.run_path(VERIFIER)
    if sys.argv[1] == "open":
        open_mapping(expected, api)
    else:
        ready(expected, api)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Catalog model unavailable; inference remains disabled.", file=sys.stderr)
        sys.exit(1)
