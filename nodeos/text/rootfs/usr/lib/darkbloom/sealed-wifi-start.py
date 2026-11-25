#!/usr/bin/python3
"""Release-bound Wi-Fi handoff before NetworkManager; never logs credentials."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HOST = Path("/run/nodeos/host")
OUTPUT = Path("/run/NetworkManager/system-connections/darkbloom-wifi.nmconnection")
STATUS = Path("/run/darkbloom-wifi/status.json")
UNSEAL = "/usr/lib/darkbloom/sealed-wifi-unseal.py"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def protected(info):
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unprotected handoff path")


def install_id(cmdline):
    roots = [word.removeprefix("nodeos.root=") for word in cmdline.split() if word.startswith("nodeos.root=")]
    if len(roots) != 1:
        raise ValueError("Missing or duplicate signed root path")
    match = re.fullmatch(r"/var/lib/darkbloom-text-nodeos/([A-Za-z0-9][A-Za-z0-9._-]{0,79})/root\.erofs", roots[0])
    if not match:
        raise ValueError("Unexpected signed root path")
    return match[1]


def inspect_blob(host, release):
    """Only an absent literal blob permits offline calibration; never networking."""
    directory = os.open(host, DIR_FLAGS)
    try:
        protected(os.fstat(directory))
        for name in ("var", "lib", "darkbloom-text-nodeos", release):
            child = os.open(name, DIR_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
            protected(os.fstat(directory))
        try:
            descriptor = os.open("wifi-sealed.json", FILE_FLAGS, dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            protected(info)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 128 * 1024:
                raise ValueError("Invalid sealed Wi-Fi object")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    return host / "var/lib/darkbloom-text-nodeos" / release / "wifi-sealed.json"


def prepare_output(output):
    # /run and its parents are the trusted RAM filesystem. Refuse symlinked or
    # writable directories rather than following a changed NetworkManager path.
    directory = os.open("/", DIR_FLAGS)
    try:
        for name in output.parent.parts[1:]:
            try:
                child = os.open(name, DIR_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                os.mkdir(name, 0o700, dir_fd=directory)
                child = os.open(name, DIR_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
            protected(os.fstat(directory))
        os.fchmod(directory, 0o700)
        # A failed/repeated start cannot reuse a previously decrypted profile.
        try:
            os.unlink(output.name, dir_fd=directory)
        except FileNotFoundError:
            pass
    finally:
        os.close(directory)


def start(cmdline, host=HOST, output=OUTPUT):
    release = install_id(cmdline)
    prepare_output(output)
    blob = inspect_blob(host, release)
    if blob is None:
        return False
    try:
        subprocess.run(["/usr/bin/python3", "-I", "-B", UNSEAL,
                        "--blob", str(blob), "--out", str(output)],
                       check=True, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=ENV, timeout=60)
        descriptor = os.open(output, FILE_FLAGS)
        try:
            info = os.fstat(descriptor)
            protected(info)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 32768:
                raise ValueError("Invalid decrypted Wi-Fi handoff")
        finally:
            os.close(descriptor)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return True


def save_status(available):
    raw = (json.dumps({"v": 1, "sealed_wifi_available": available}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = STATUS.with_name("status.new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        os.replace(temporary, STATUS)
    finally:
        temporary.unlink(missing_ok=True)
    sys.stdout.write(raw.decode())


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError("Fixed root operation required")
    STATUS.unlink(missing_ok=True)
    available = start(Path("/proc/cmdline").read_text())
    save_status(available)
    if not available:
        # The fixed calibration unit has the only ESP write privilege. This
        # credential service retains no mount capability and never starts NM.
        subprocess.run(["/usr/bin/systemctl", "start", "darkbloom-offline-calibration.service"],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env=ENV, timeout=120)
        raise ValueError("No sealed Wi-Fi credential")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        # Never forward TPM/decryptor stderr or a parsed connection property.
        print("Sealed Wi-Fi handoff failed; NetworkManager remains blocked.", file=sys.stderr)
        sys.exit(1)
