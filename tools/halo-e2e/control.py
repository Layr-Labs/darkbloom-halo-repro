#!/usr/bin/env python3
"""Root-owned, fixed-operation Halo POC controller. No user-supplied code paths."""
import base64
import configparser
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

LIB = Path("/usr/local/libexec/darkbloom-text-e2e")
STATE = Path("/var/lib/darkbloom-text-e2e")
CONFIG = STATE / "device.json"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}
sys.path.insert(0, str(LIB))
from bundle import open_dir, read_regular, parse_manifest, verify_signature, copy_payload
from device_config import load as load_device


def device():
    config = load_device(CONFIG)
    info = CONFIG.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("device config is not root-protected")
    return config


def esp_path():
    return Path(device()["esp_mount"])


def staging_path():
    return Path("/home") / device()["owner_user"] / "darkbloom-text-e2e-staging"


def run(args, *, capture=True, extra_env=None):
    return subprocess.run(args, check=True, env=ENV | (extra_env or {}),
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None).stdout


def sha(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(4*1024*1024), b""):
            result.update(data)
    return result.hexdigest()


def save(name, value):
    target = STATE / name
    temporary = STATE / (name + ".tmp")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load(name):
    return json.loads((STATE / name).read_text())


def boot_state():
    text = run(["/usr/bin/efibootmgr", "-v"]).decode()
    match = re.search(r"^BootOrder: ([0-9A-Fa-f,]+)$", text, re.M)
    if not match or not re.fullmatch(r"[0-9A-Fa-f]{4}(,[0-9A-Fa-f]{4})*", match[1]):
        raise ValueError("Cannot read BootOrder")
    entries = {m[1].upper(): m[2] for m in re.finditer(r"^Boot([0-9A-Fa-f]{4})\*?\s+(.*)$", text, re.M)}
    return match[1].upper().split(","), entries


def check_esp():
    config = device()
    mounted = run(["/usr/bin/findmnt", "-n", "--types", "vfat", "-o", "SOURCE", config["esp_mount"]]).decode().strip()
    if not mounted or Path(mounted).resolve(strict=True) != Path(config["esp_device"]).resolve(strict=True):
        raise ValueError("Unexpected ESP mount")
    if run(["/usr/sbin/blkid", "-s", "PARTUUID", "-o", "value", config["esp_device"]]).decode().strip().lower() != config["esp_partuuid"]:
        raise ValueError("Unexpected ESP partition")
    if sha(STATE / "trust/boot-cert.der") != config["mok_cert_sha256"]:
        raise ValueError("Pinned boot certificate changed")


def verify_factory():
    esp = esp_path()
    for name, digest in load("factory-files.json").items():
        path = esp / name
        if path.is_symlink() or not path.is_file() or sha(path) != digest:
            raise ValueError("Factory EFI file changed: " + name)
    _, entries = boot_state()
    for entry, original in load("original-boot.json")["entries"].items():
        if entries.get(entry) != original:
            raise ValueError("Original boot entry changed: Boot" + entry)


def check_bootnext():
    text = run(["/usr/bin/efibootmgr"]).decode()
    match = re.search(r"^BootNext: ([0-9A-Fa-f]{4})$", text, re.M)
    if match:
        own = None
        if (STATE / "current.json").exists():
            current = load("current.json")
            own = (Path("/var/lib/darkbloom-text-nodeos") / current["install_id"] / "boot-id").read_text().strip().upper()
        if match[1].upper() != own:
            raise ValueError("Unrelated BootNext exists; refusing to change it")
    return bool(match)


def check_sidecars(install_id):
    # systemd-stub consumes these outside the signed PE image. Never calibrate
    # a release with owner-supplied sidecars folded into its first observed PCRs.
    esp = esp_path()
    for path in (esp / "loader/addons", esp / "loader/credentials",
                 esp / "EFI/darkbloom-text" / install_id / "grubx64.efi.extra.d"):
        if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
            raise ValueError("Unexpected UKI sidecars: " + str(path))


def reconcile_order():
    """Only undo a proven factory-fallback prefix; unknown owner changes fail."""
    expected = load("original-boot.json")["order"]
    current, entries = boot_state()
    if current == expected:
        return
    if len(current) <= len(expected) or current[-len(expected):] != expected:
        raise ValueError("Unrelated BootOrder change; refusing to overwrite it")
    extras = current[:-len(expected)]
    if len(set(extras)) != len(extras) or set(extras) & set(expected):
        raise ValueError("Unexpected BootOrder transformation")
    config = device()
    for entry in extras:
        line = entries.get(entry, "").lower()
        label, separator, device_entry = line.partition("\t")
        efi_shim = "\\" + config["factory_efi_dir"].replace("/", "\\") + "\\shimx64.efi"
        if (not separator or label.strip() != config["factory_boot_label"].lower()
                or "hd(" + str(config["esp_partition"]) + ",gpt," + config["esp_partuuid"] + "," not in device_entry
                or "file(" + efi_shim.lower() + ")" not in device_entry):
            raise ValueError("Unrecognized boot prefix; refusing to overwrite it")
    run(["/usr/bin/efibootmgr", "--bootorder", ",".join(expected)])
    if boot_state()[0] != expected:
        raise ValueError("BootOrder reconciliation did not stick")


def install():
    check_esp()
    verify_factory()
    check_bootnext()
    reconcile_order()
    staging_fd = open_dir(staging_path())
    try:
        raw = read_regular(staging_fd, "manifest.json", 32768)
        signature = read_regular(staging_fd, "manifest.sig", 8192)
        manifest = parse_manifest(raw)
        check_sidecars(manifest["install_id"])
        previous = load("sequence.json")["sequence"]
        if manifest["sequence"] <= previous:
            raise ValueError("Release sequence must increase")
        destination = STATE / "bundles" / (str(manifest["sequence"]) + "-" + manifest["install_id"])
        if destination.exists():
            raise ValueError("Bundle already exists")
        with tempfile.TemporaryDirectory(prefix="verify-", dir=STATE) as temporary:
            temporary = Path(temporary)
            verify_signature(raw, signature, STATE / "trust/boot-public.pem", temporary)
            copy_payload(staging_fd, manifest, temporary)
            # Accept only verified immutable bytes, before any privileged installer runs.
            os.rename(temporary, destination)
        save("sequence.json", {"sequence": manifest["sequence"]})
    finally:
        os.close(staging_fd)
    install_id = manifest["install_id"]
    run(["/bin/bash", str(LIB / "install.sh"), "install"], capture=False,
        extra_env={"NODEOS_TEXT_WORK": str(destination), "ID": install_id})
    save("current.json", {"bundle": destination.name, "install_id": install_id,
                          "sequence": manifest["sequence"]})
    print(json.dumps({"installed": install_id, "sequence": manifest["sequence"], "rebooted": False}))


def installed_action(operation):
    current = load("current.json")
    bundle = STATE / "bundles" / current["bundle"]
    manifest = parse_manifest((bundle / "manifest.json").read_bytes())
    if manifest["install_id"] != current["install_id"] or manifest["sequence"] != current["sequence"]:
        raise ValueError("Installed state mismatch")
    check_sidecars(current["install_id"])
    run(["/bin/bash", str(LIB / "install.sh"), operation], capture=False,
        extra_env={"NODEOS_TEXT_WORK": str(bundle), "ID": current["install_id"]})


def wifi_profile():
    uuid = run(["/usr/bin/nmcli", "-g", "GENERAL.CON-UUID", "device", "show", device()["wifi_iface"]]).decode().strip()
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
        raise ValueError("No active pinned Wi-Fi connection UUID")
    directory = open_dir("/etc/NetworkManager/system-connections")
    matches = []
    try:
        for name in os.listdir(directory):
            try:
                data = read_regular(directory, name, 1024*1024)
                parser = configparser.ConfigParser(interpolation=None)
                parser.read_string(data.decode())
                if parser.get("connection", "uuid", fallback="").lower() == uuid.lower():
                    matches.append(data)
            except (ValueError, OSError, UnicodeError, configparser.Error):
                continue
    finally:
        os.close(directory)
    if len(matches) != 1:
        raise ValueError("Active Wi-Fi profile is absent or ambiguous")
    sys.stdout.buffer.write(matches[0])


def main():
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(ENV)
    if os.geteuid() != 0 or os.uname().nodename != device()["hostname"]:
        raise ValueError("This helper is restricted to root on the pinned device")
    args = sys.argv[1:]
    if (not args or args[0] not in {"status", "ek-chain", "quote", "wifi-profile", "install", "boot", "cleanup"}
            or len(args) != (2 if args[0] == "quote" else 1)
            or (args[0] == "quote" and not re.fullmatch(r"[0-9a-fA-F]{64}", args[1]))):
        raise ValueError("Invalid fixed operation/arguments")
    with (STATE / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        operation = args[0]
        if operation == "status":
            order, _ = boot_state()
            print(json.dumps({"boot_order": order, "original_boot_order": load("original-boot.json")["order"],
                              "last_accepted_sequence": load("sequence.json")["sequence"],
                              "installed": load("current.json") if (STATE / "current.json").exists() else None,
                              "secure_boot": run(["/usr/bin/mokutil", "--sb-state"]).decode().strip()}))
        elif operation == "wifi-profile":
            if (STATE / "current.json").exists():
                raise ValueError("Wi-Fi export is disabled after the first successful install")
            wifi_profile()
        elif operation == "ek-chain":
            with tempfile.TemporaryDirectory(prefix="ek-", dir=STATE) as directory:
                report = run(["/usr/bin/python3", "-I", str(LIB / "read_ek_chain.py"), directory]).decode()
                files = {path.name: base64.b64encode(path.read_bytes()).decode()
                         for path in sorted(Path(directory).glob("*.der"))}
                print(json.dumps({"report": report, "files_base64": files}))
        elif operation == "quote":
            sys.stdout.buffer.write(run(["/usr/bin/python3", "-I", str(LIB / "collect_quote.py"), args[1]]))
        elif operation == "install":
            install()
        elif operation == "boot":
            check_esp()
            verify_factory()
            check_bootnext()
            reconcile_order()
            installed_action("verify")
            installed_action("boot-once")
        elif operation == "cleanup":
            try:
                check_esp()
                verify_factory()
                has_bootnext = check_bootnext()
                reconcile_order()
                if has_bootnext:
                    run(["/usr/bin/efibootmgr", "--delete-bootnext"])
            finally:
                # Revocation must remain possible even if unrelated boot/file
                # changes require manual recovery rather than restoration.
                Path("/etc/sudoers.d/darkbloom-text-e2e").unlink(missing_ok=True)
            print("Original factory EFI hashes and BootOrder verified; own sudo grant removed. Images and SSH authorization retained.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, KeyError) as error:
        # Do not include subprocess stdout/stderr: Wi-Fi exports may contain secrets.
        print("Darkbloom operation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
