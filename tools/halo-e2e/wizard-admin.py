#!/usr/bin/env python3
"""Fixed setup operations for a pre-staged, signed Halo test release."""
import configparser
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, "/usr/local/libexec/darkbloom-text-e2e")
import control
from bundle import open_dir, read_regular, verify_signature

STATE = Path("/var/lib/darkbloom-halo-setup")
DATA = Path("/var/lib/darkbloom-text-nodeos")
PROFILE_DIR = Path("/etc/NetworkManager/system-connections")
ENTRY_ID = "darkbloom-halo-wizard.conf"
PCRS = {"4", "7", "9", "11", "12", "14"}
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
NONCE_RE = re.compile(rb"[0-9a-f]{64}\n")
MAX_EVIDENCE = 256 * 1024


def run(*args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=control.ENV)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed")
    return result.stdout


def atomic_write(path, payload, mode=None):
    fd, temp = tempfile.mkstemp(prefix=".darkbloom-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            if mode is not None:
                os.fchmod(out.fileno(), mode)
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def checked_release():
    control.check_esp()
    control.verify_factory()
    if control.check_bootnext():
        raise ValueError("A firmware one-shot selection is already pending")
    order, _ = control.boot_state()
    if order != control.load("original-boot.json")["order"]:
        raise ValueError("Factory firmware boot order changed")
    if run("/usr/bin/mokutil", "--sb-state").decode().strip() != "SecureBoot enabled":
        raise ValueError("Secure Boot must be enabled")
    release = control.load("current.json")["install_id"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", release):
        raise ValueError("Invalid installed release identifier")
    if release != (STATE / "release").read_text().strip():
        raise ValueError("Staged boot image differs from the setup release")
    control.check_sidecars(release)
    esp = control.ESP if hasattr(control, "ESP") else control.esp_path()
    relative = f"/EFI/darkbloom-text/{release}/grubx64.efi"
    uki = esp / relative.lstrip("/")
    expected = (DATA / release / "uki.sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or control.sha(uki) != expected:
        raise ValueError("Installed UKI failed its integrity check")
    entry = esp / "loader/entries" / ENTRY_ID
    record = f"title Darkbloom\nsort-key darkbloom\nefi {relative}\n".encode()
    return release, esp, entry, record


def bootctl(esp, *args):
    return run("/usr/bin/bootctl", "--esp-path", str(esp), *args)


def entries(esp):
    rows = json.loads(bootctl(esp, "list", "--json=short"))
    if not isinstance(rows, list):
        raise ValueError("Unexpected boot manager response")
    return rows


def valid_default(rows):
    default = [row for row in rows if row.get("isDefault") is True]
    if (len(default) != 1
            or not re.fullmatch(r"amd-ryzen-ai-developer-platform-[A-Za-z0-9.+_-]+\.conf", default[0].get("id", ""))):
        raise ValueError("Factory AMD Linux is not the current default")
    return default[0]["id"]


def check_menu(esp, entry, record):
    if not entry.is_file() or entry.is_symlink() or entry.read_bytes() != record:
        return False
    rows = entries(esp)
    valid_default(rows)
    found = [r for r in rows if r.get("id") == ENTRY_ID and r.get("title") == "Darkbloom"]
    return len(found) == 1 and found[0].get("efi") == record.decode().split("efi ", 1)[1].strip()


def prepare_menu(esp, entry, record):
    valid_default(entries(esp))
    if entry.exists() or entry.is_symlink():
        if not check_menu(esp, entry, record):
            raise ValueError("Existing Darkbloom menu entry differs from the staged release")
    else:
        # VFAT assigns its permissions at mount time.
        atomic_write(entry, record)
        try:
            if not check_menu(esp, entry, record):
                raise ValueError("Boot manager did not list both OSes")
        except Exception:
            entry.unlink()
            raise


def wifi_uuid():
    iface = (STATE / "wifi-interface").read_text().strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", iface):
        raise ValueError("Invalid pinned Wi-Fi interface")
    uuid = run("/usr/bin/nmcli", "-g", "GENERAL.CON-UUID", "device", "show", iface).decode().strip()
    return uuid if re.fullmatch(r"[a-fA-F0-9-]{36}", uuid) else None


def active_wifi():
    uuid = wifi_uuid()
    if uuid is None:
        raise ValueError("The pinned Wi-Fi interface has no active profile")
    found = []
    directory = open_dir(PROFILE_DIR)
    try:
        for name in os.listdir(directory):
            try:
                profile = read_regular(directory, name, 16384)
                parsed = configparser.ConfigParser(interpolation=None)
                parsed.read_string(profile.decode())
                if parsed.get("connection", "uuid", fallback="").lower() == uuid.lower():
                    found.append(profile)
            except (ValueError, OSError, configparser.Error):
                continue
    finally:
        os.close(directory)
    if len(found) != 1:
        raise ValueError("The current Wi-Fi profile is not available as a system keyfile")
    return found[0]


def checked_pcr_file(path, release):
    raw = path.read_bytes()
    data = json.loads(raw)
    if (len(raw) > 4096 or set(data) != {"v", "bank", "install_id", "pcrs"} or data["v"] != 1
            or data["bank"] != "sha256" or data["install_id"] != release
            or set(data["pcrs"]) != PCRS
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in data["pcrs"].values())):
        raise ValueError("Invalid calibration PCR file")
    return raw


def staging_dir():
    return open_dir(Path((STATE / "staging").read_text().strip()))


def calibration_dir(esp, release):
    return esp / "EFI/darkbloom-text" / release / "calibration"


def read_calibration_report(path):
    fd = open_dir(path)
    try:
        return read_regular(fd, "evidence.json", MAX_EVIDENCE)
    finally:
        os.close(fd)


def calibrate(esp, release):
    if (STATE / "expected-pcrs.json").exists():
        raise ValueError("Calibration pins are already armed")
    fd = staging_dir()
    try:
        nonce = read_regular(fd, "calibration-nonce", 65)
    finally:
        os.close(fd)
    if not NONCE_RE.fullmatch(nonce):
        raise ValueError("A fresh 32-byte calibration nonce is required")
    path = calibration_dir(esp, release)
    path.mkdir(exist_ok=True)
    fd = open_dir(path)
    try:
        if set(os.listdir(fd)) - {"nonce", "evidence.json"}:
            raise ValueError("Unexpected calibration directory contents")
        if "nonce" in os.listdir(fd) and read_regular(fd, "nonce", 65) == nonce:
            raise ValueError("Use a fresh calibration nonce for each attempt")
        (path / "evidence.json").unlink(missing_ok=True)
        atomic_write(path / "nonce", nonce)
    finally:
        os.close(fd)
    reboot_into_entry(esp)


def arm(release, esp):
    calibration = calibration_dir(esp, release)
    pins = STATE / "expected-pcrs.json"
    if not pins.exists():
        read_calibration_report(calibration)
    fd = staging_dir()
    try:
        raw = read_regular(fd, "expected-pcrs.json", 4096)
        sig = read_regular(fd, "expected-pcrs.sig", 8192)
    finally:
        os.close(fd)
    with tempfile.TemporaryDirectory(dir=STATE, prefix="arm-") as tmp:
        verify_signature(raw, sig, control.STATE / "trust/boot-public.pem", Path(tmp))
        path = Path(tmp) / "pins.json"
        path.write_bytes(raw)
        checked_pcr_file(path, release)
    if pins.exists() and checked_pcr_file(pins, release) != raw:
        raise ValueError("Calibration pins already differ from the staged pins")
    atomic_write(pins, raw, 0o600)
    if calibration.exists():
        (calibration / "nonce").unlink(missing_ok=True)
        (calibration / "evidence.json").unlink(missing_ok=True)
        calibration.rmdir()


def reboot_into_entry(esp):
    efivars = Path("/sys/firmware/efi/efivars")
    if any((efivars / f"{name}-{LOADER_GUID}").exists()
           for name in ("LoaderEntryOneShot", "LoaderConfigTimeoutOneShot")):
        raise ValueError("A boot manager one-shot selection is already pending")
    bootctl(esp, "set-oneshot", ENTRY_ID)
    try:
        # systemd-boot v257 forces the menu whenever this override is set.
        # Give the selected entry a countdown so it boots without a keypress.
        bootctl(esp, "set-timeout-oneshot", "1")
        run("/usr/bin/sync")
        run("/usr/bin/systemctl", "reboot")
    except Exception:
        bootctl(esp, "set-oneshot", "")
        bootctl(esp, "set-timeout-oneshot", "")
        raise


def finish(release, esp):
    pcr_file = STATE / "expected-pcrs.json"
    checked_pcr_file(pcr_file, release)
    if calibration_dir(esp, release).exists():
        raise ValueError("Remove the calibration request by arming the signed pins")
    target = DATA / release / "wifi-sealed.json"
    if target.exists() or target.is_symlink():
        raise ValueError("The Wi-Fi credential already exists")
    profile = active_wifi()
    run("/usr/bin/python3", "-I", str(HERE / "sealed-wifi-seal.py"),
        "--profile-fd", "0", "--expected-pcrs", str(pcr_file),
        "--install-id", release, "--out", str(target), data=profile)
    del profile
    try:
        attempt = subprocess.run(
            ["/usr/bin/python3", "-I", str(HERE / "sealed-wifi-check.py"),
             "--blob", str(target)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=control.ENV)
        if attempt.returncode != 3:
            raise ValueError("Unable to confirm the factory boot differs from the pinned PCRs")
        factory = valid_default(entries(esp))
        bootctl(esp, "set-default", factory)
        bootctl(esp, "set-timeout", "6")
        reboot_into_entry(esp)
    except Exception:
        target.unlink(missing_ok=True)
        raise


def main(operation):
    if os.geteuid() or "nodeos.root=" in Path("/proc/cmdline").read_text():
        raise ValueError("Setup operations require the factory OS and root")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release, esp, entry, record = checked_release()
        if operation == "prepare-menu":
            prepare_menu(esp, entry, record)
            return
        menu_ready = check_menu(esp, entry, record)
        if not menu_ready:
            raise ValueError("The persistent Darkbloom boot menu entry is not installed")
        completed = (DATA / release / "wifi-sealed.json").is_file()
        if operation == "status":
            connected = wifi_uuid() is not None
            ready = (STATE / "expected-pcrs.json").is_file() and not calibration_dir(esp, release).exists()
            print(json.dumps(dict(ready=ready, release_id=release, connected_wifi=connected,
                                  menu_ready=menu_ready, completed=completed)))
        elif operation == "calibration-key" and not completed:
            sys.stdout.buffer.write(run(
                "/usr/bin/python3", "-I", str(HERE / "collect_quote.py"), "--calibration-key"))
        elif operation == "calibrate" and not completed:
            calibrate(esp, release)
        elif operation == "calibration-report" and not completed:
            sys.stdout.buffer.write(read_calibration_report(calibration_dir(esp, release)))
        elif operation == "arm" and not completed:
            arm(release, esp)
        elif operation == "finish" and not completed:
            finish(release, esp)
        else:
            raise ValueError("Invalid setup operation or setup already completed")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Exactly one fixed operation is required")
        main(sys.argv[1])
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print("Darkbloom setup check failed. The approved image, network, or boot menu needs review.",
              file=sys.stderr)
        sys.exit(1)
