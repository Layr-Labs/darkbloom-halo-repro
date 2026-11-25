#!/usr/bin/python3
"""Export one requested public TPM quote; never enable network or inference."""
import base64
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import stat
import subprocess
import sys
import time

CONFIG = Path("/usr/share/darkbloom/offline-calibration.json")
MOUNT = Path("/run/darkbloom-calibration/esp")
COLLECTOR = "/usr/lib/darkbloom/collect_quote.py"
WIFI = "/usr/lib/darkbloom/sealed-wifi-start.py"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_EVIDENCE = 256 * 1024
PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 14]
UNITS = ("NetworkManager.service", "dbnode-engine.service", "dbnode-llama.service", "dbnode.service")


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate public field")
        value[key] = item
    return value


def esp_config(cmdline, raw):
    values = [word[len("nodeos.esp-partuuid="):] for word in cmdline.split() if word.startswith("nodeos.esp-partuuid=")]
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values[0]):
        raise ValueError("Missing or duplicate signed ESP pin")
    config = json.loads(raw, object_pairs_hook=no_duplicates)
    if (not isinstance(config, dict) or set(config) != {"v", "esp_device", "esp_partuuid"}
            or type(config["v"]) is not int or config["v"] != 1
            or config["esp_partuuid"] != values[0] or not isinstance(config["esp_device"], str)
            or not re.fullmatch(r"/dev/[A-Za-z0-9._/-]{1,96}", config["esp_device"])
            or any(part in (".", "..") for part in config["esp_device"].split("/"))
            or "//" in config["esp_device"]):
        raise ValueError("ESP configuration differs from signed pin")
    return config


def command(args):
    return subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=ENV, timeout=10).stdout


def pinned_partition(source, partuuid, sysfs=Path("/sys/dev/block")):
    device = os.stat(source, follow_symlinks=False)
    if not stat.S_ISBLK(device.st_mode):
        raise ValueError("ESP source is not a block device")
    number = f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}"
    identity = (sysfs / number / "uevent").read_bytes().splitlines()
    if b"DEVTYPE=partition" not in identity or f"PARTUUID={partuuid}".encode("ascii") not in identity:
        raise ValueError("ESP partition differs from signed pin")


def credential_free(release):
    wifi = runpy.run_path(WIFI)
    if wifi["inspect_blob"](wifi["HOST"], release) is not None:
        raise ValueError("Calibration requires an absent sealed credential")
    directory = Path("/run/NetworkManager/system-connections")
    if directory.is_symlink() or (directory.exists() and any(directory.iterdir())):
        raise ValueError("Calibration requires no runtime network profile")
    for unit in UNITS:
        state = command(["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"]).strip()
        if state not in (b"inactive", b"failed"):
            raise ValueError("Network or application is already running")


def read_at(directory, name, maximum):
    descriptor = os.open(name, FILE_FLAGS, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError("Invalid calibration file")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != info.st_size or len(raw) > maximum:
            raise ValueError("Changed calibration file")
        return raw
    finally:
        os.close(descriptor)


def request_directory(mount, release):
    directory = os.open(mount, DIR_FLAGS)
    try:
        for name in ("EFI", "darkbloom-text", release, "calibration"):
            try:
                child = os.open(name, DIR_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                if name == "calibration":
                    return None
                raise
            os.close(directory)
            directory = child
        if set(os.listdir(directory)) != {"nonce"}:
            raise ValueError("Unexpected calibration directory contents")
        nonce = read_at(directory, "nonce", 65)
        if not re.fullmatch(b"[0-9a-f]{64}\n", nonce):
            raise ValueError("Invalid calibration nonce")
        result = directory
        directory = None
        return result, nonce
    finally:
        if directory is not None:
            os.close(directory)


def capture(nonce):
    """Bound child stdout before storing it; no journal or credential export."""
    process = subprocess.Popen(["/usr/bin/python3", "-I", COLLECTOR, "--calibration", nonce.decode().strip()],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=ENV)
    result = bytearray()
    deadline = time.monotonic() + 60
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ValueError("Calibration capture timed out")
            chunk = os.read(process.stdout.fileno(), min(65536, MAX_EVIDENCE + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > MAX_EVIDENCE:
                raise ValueError("Calibration capture exceeded limit")
        if process.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
            raise ValueError("Calibration collector failed")
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return validate_evidence(bytes(result))


def validate_evidence(raw):
    if not 0 < len(raw) <= MAX_EVIDENCE:
        raise ValueError("Invalid calibration evidence size")
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    fields = {"quoted_pcrs", "ak_public", "attest", "signature", "pcr_read_sha256", "event_log"}
    if not isinstance(value, dict) or set(value) != fields or value["quoted_pcrs"] != PCRS:
        raise ValueError("Unexpected calibration evidence schema")
    if not isinstance(value["pcr_read_sha256"], dict) or set(value["pcr_read_sha256"]) != {str(pcr) for pcr in PCRS}:
        raise ValueError("Incomplete calibration PCRs")
    if any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in value["pcr_read_sha256"].values()):
        raise ValueError("Malformed calibration PCR value")
    for field in ("ak_public", "attest", "signature"):
        if not isinstance(value[field], str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value[field]):
            raise ValueError("Malformed public TPM field")
    if not isinstance(value["event_log"], str) or not base64.b64decode(value["event_log"], validate=True):
        raise ValueError("Missing measured boot log")
    return raw


def publish(directory, nonce, evidence):
    validate_evidence(evidence)
    if set(os.listdir(directory)) != {"nonce"} or read_at(directory, "nonce", 65) != nonce:
        raise ValueError("Calibration request changed")
    temporary = "evidence.json.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(evidence)
            stream.flush()
            os.fsync(descriptor)
        if set(os.listdir(directory)) != {"nonce", temporary} or read_at(directory, "nonce", 65) != nonce:
            raise ValueError("Calibration request changed during export")
        os.rename(temporary, "evidence.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def main():
    os.umask(0o077)
    phase = "calibration prerequisites"
    try:
        if os.geteuid() != 0 or len(sys.argv) != 1:
            raise ValueError("Fixed root operation required")
        cmdline = Path("/proc/cmdline").read_text()
        release = runpy.run_path(WIFI)["install_id"](cmdline)
        config = esp_config(cmdline, CONFIG.read_bytes())
        credential_free(release)
        phase = "EFI partition identification"
        source = config["esp_device"]
        pinned_partition(source, config["esp_partuuid"])
        phase = "read-only EFI mount"
        MOUNT.mkdir(mode=0o700)
        if MOUNT.is_symlink() or os.path.ismount(MOUNT) or any(MOUNT.iterdir()):
            raise ValueError("Unexpected calibration mount point")
        command(["/usr/bin/mount", "-i", "-n", "-t", "vfat", "-o",
                 "ro,nosuid,nodev,noexec,uid=0,gid=0,umask=0077", source, str(MOUNT)])
        directory = None
        try:
            phase = "calibration challenge"
            request = request_directory(MOUNT, release)
            if request is None:
                print('{"offline_calibration_exported":false}')
                return 0
            directory, nonce = request
            phase = "TPM quote and boot event log"
            evidence = capture(nonce)
            phase = "offline service check"
            credential_free(release)
            phase = "writable EFI remount"
            command(["/usr/bin/mount", "-i", "-n", "-t", "vfat", "-o",
                     "remount,rw,nosuid,nodev,noexec,uid=0,gid=0,umask=0077", source, str(MOUNT)])
            phase = "TPM report export"
            publish(directory, nonce, evidence)
            phase = "EFI unmount"
        finally:
            if directory is not None:
                os.close(directory)
            command(["/usr/bin/umount", "-i", "-n", str(MOUNT)])
    except (OSError, ValueError, subprocess.SubprocessError):
        print(f"Darkbloom calibration stopped at {phase}. Wi-Fi and inference are disabled.",
              file=sys.stderr, flush=True)
        return 1
    print('{"offline_calibration_exported":true}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
