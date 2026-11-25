#!/usr/bin/env python3
"""Seal a Wi-Fi keyfile for one reviewed Darkbloom boot, or unseal it there.

The factory-side command reads the profile from an inherited descriptor. It
never accepts a pathname for plaintext or prints it. The sealed-side command
only accepts the fixed host-image and runtime NetworkManager paths. This is a
single-release PolicyPCR design: a changed boot requires a new sealed blob.
"""

import argparse
import base64
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


PCRS = (4, 7, 9, 11, 12, 14)
PCR_SELECTION = "sha256:" + ",".join(map(str, PCRS))
DOMAIN = "darkbloom-sealed-wifi/v1"
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
HOST_PREFIX = "/run/nodeos/host/var/lib/darkbloom-text-nodeos/"
HOST_BASENAME = "wifi-sealed.json"
NETWORK_OUTPUT = "/run/NetworkManager/system-connections/darkbloom-wifi.nmconnection"
MAX_PROFILE = 32 * 1024
MAX_BLOB = 128 * 1024
MAX_TPM_BLOB = 32 * 1024
TPM_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TPM2TOOLS_TCTI": "device:/dev/tpmrm0"}


class SealedWifiError(Exception):
    """A deliberately content-free, user-facing failure."""


class PcrMismatch(SealedWifiError):
    """The TPM responded, but its live PCR values differ from the pin."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SealedWifiError("invalid public metadata")
        out[key] = value
    return out


def parse_canonical(raw, maximum):
    if not 0 < len(raw) <= maximum:
        raise SealedWifiError("invalid public metadata")
    try:
        obj = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise SealedWifiError("invalid public metadata") from exc
    if raw != canonical(obj):
        raise SealedWifiError("noncanonical public metadata")
    return obj


def validate_pcrs(value):
    if not isinstance(value, dict) or set(value) != {str(p) for p in PCRS}:
        raise SealedWifiError("expected six exact SHA-256 PCR values")
    if any(not isinstance(value[str(p)], str) or not HEX_RE.fullmatch(value[str(p)]) for p in PCRS):
        raise SealedWifiError("expected six exact SHA-256 PCR values")
    return value


def validate_id(value):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise SealedWifiError("invalid install ID")
    return value


def parse_expected(raw, install_id):
    value = parse_canonical(raw, 4096)
    if (not isinstance(value, dict) or set(value) != {"v", "bank", "install_id", "pcrs"}
            or type(value["v"]) is not int or value["v"] != 1
            or value["bank"] != "sha256" or value["install_id"] != install_id):
        raise SealedWifiError("PCR reference does not name this install")
    validate_pcrs(value["pcrs"])
    return value["pcrs"]


def raw_pcr_values(pcrs):
    return b"".join(bytes.fromhex(pcrs[str(p)]) for p in PCRS)


def normalize_profile(raw):
    if not 0 < len(raw) <= MAX_PROFILE or b"\x00" in raw:
        raise SealedWifiError("invalid Wi-Fi profile")
    try:
        profile = configparser.ConfigParser(interpolation=None, strict=True)
        profile.optionxform = str
        profile.read_string(raw.decode("utf-8"))
        if profile.get("connection", "type") not in ("wifi", "802-11-wireless"):
            raise ValueError("not Wi-Fi")
        section = next((s for s in ("wifi-security", "802-11-wireless-security") if profile.has_section(s)), None)
        if section is None or profile.get(section, "key-mgmt") not in ("wpa-psk", "sae"):
            raise ValueError("unsupported Wi-Fi authentication")
        if not profile.get(section, "psk"):
            raise ValueError("missing PSK")
        profile["connection"]["permissions"] = ""
        profile["connection"]["autoconnect"] = "true"
        profile[section]["psk-flags"] = "0"
        output = io.StringIO()
        profile.write(output, space_around_delimiters=False)
        normalized = output.getvalue().encode("utf-8")
        if len(normalized) > MAX_PROFILE:
            raise ValueError("oversized normalized profile")
        return normalized
    except (UnicodeError, ValueError, configparser.Error, KeyError) as exc:
        raise SealedWifiError("invalid Wi-Fi profile") from exc


def read_profile_fd(fd):
    if fd < 0 or os.isatty(fd):
        raise SealedWifiError("a non-terminal profile descriptor is required")
    raw = bytearray()
    while len(raw) <= MAX_PROFILE:
        part = os.read(fd, min(4096, MAX_PROFILE + 1 - len(raw)))
        if not part:
            break
        raw.extend(part)
    if len(raw) > MAX_PROFILE:
        raise SealedWifiError("invalid Wi-Fi profile")
    try:
        return normalize_profile(raw)
    finally:
        raw[:] = b"\x00" * len(raw)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value, maximum):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise SealedWifiError("invalid sealed blob")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SealedWifiError("invalid sealed blob") from exc
    if len(raw) > maximum or b64(raw) != value:
        raise SealedWifiError("invalid sealed blob")
    return raw


def tpm(command, *args, input_bytes=None, secret_output=False):
    executable = "/usr/bin/tpm2_" + command
    try:
        proc = subprocess.run([executable, "-Q", *map(str, args)], input=input_bytes,
                              stdout=subprocess.PIPE if secret_output else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False, env=TPM_ENV, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SealedWifiError("TPM operation failed") from exc
    if proc.returncode != 0:
        raise SealedWifiError("TPM operation failed")
    return proc.stdout if secret_output else b""


def flush(path):
    if path.exists():
        try:
            tpm("flushcontext", path)
        except SealedWifiError:
            pass


def build_policy(work, pcrs):
    values = work / "expected-pcrs.bin"
    values.write_bytes(raw_pcr_values(pcrs))
    session = work / "trial.ctx"
    policy = work / "policy.bin"
    try:
        tpm("startauthsession", "-S", session)
        tpm("policypcr", "-S", session, "-l", PCR_SELECTION, "-f", values, "-L", policy)
    finally:
        flush(session)
    digest = policy.read_bytes()
    if len(digest) != 32:
        raise SealedWifiError("TPM policy digest invalid")
    return policy, values, digest


def check_live_pcrs(work, pcrs):
    observed = work / "observed-pcrs.bin"
    tpm("pcrread", "-o", observed, PCR_SELECTION)
    actual = observed.read_bytes()
    if len(actual) != 32 * len(PCRS):
        raise SealedWifiError("TPM PCR read invalid")
    if actual != raw_pcr_values(pcrs):
        raise PcrMismatch("live TPM PCRs differ from the reviewed release")


def metadata(install_id, pcrs, policy_digest, pub, priv):
    return {"v": 1, "domain": DOMAIN, "bank": "sha256", "install_id": install_id,
            "pcrs": pcrs, "policy_sha256": policy_digest.hex(),
            "tpm_public": b64(pub), "tpm_private": b64(priv)}


def validate_public(public, policy_digest):
    """Check TPM2B_PUBLIC is a policy-only keyed-hash sealing object."""
    if (len(public) < 44 or int.from_bytes(public[:2], "big") != len(public) - 2
            or public[2:4] != b"\x00\x08"  # TPM_ALG_KEYEDHASH
            or public[4:6] != b"\x00\x0b"  # TPM_ALG_SHA256
            or public[6:10] != (0x92).to_bytes(4, "big")  # fixedTPM, fixedParent, adminWithPolicy only
            or public[10:12] != b"\x00\x20"
            or public[12:44] != policy_digest):
        raise SealedWifiError("TPM object is not policy-only")


def seal(profile, pcrs, install_id, work):
    policy, _values, policy_digest = build_policy(work, pcrs)
    primary = work / "primary.ctx"
    public = work / "sealed.pub"
    private = work / "sealed.priv"
    key = bytearray(os.urandom(32))
    try:
        tpm("createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", primary)
        # Specify attributes rather than relying on tpm2-tools defaults:
        # USERWITHAUTH must be absent, so an empty password cannot bypass PCRs.
        tpm("create", "-C", primary, "-g", "sha256", "-L", policy,
            "-a", "fixedtpm|fixedparent|adminwithpolicy",
            "-i-", "-u", public, "-r", private, input_bytes=bytes(key))
        public_bytes = public.read_bytes()
        validate_public(public_bytes, policy_digest)
        head = metadata(install_id, pcrs, policy_digest, public_bytes, private.read_bytes())
        nonce = os.urandom(12)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, profile, canonical(head))
        return canonical({**head, "nonce": b64(nonce), "ciphertext": b64(ciphertext)})
    finally:
        key[:] = b"\x00" * len(key)
        flush(primary)


def parse_blob(raw, install_id):
    blob = parse_canonical(raw, MAX_BLOB)
    keys = {"v", "domain", "bank", "install_id", "pcrs", "policy_sha256",
            "tpm_public", "tpm_private", "nonce", "ciphertext"}
    if (not isinstance(blob, dict) or set(blob) != keys or type(blob["v"]) is not int or blob["v"] != 1
            or blob["domain"] != DOMAIN or blob["bank"] != "sha256" or blob["install_id"] != install_id
            or not isinstance(blob["policy_sha256"], str) or not HEX_RE.fullmatch(blob["policy_sha256"])):
        raise SealedWifiError("invalid sealed blob")
    validate_pcrs(blob["pcrs"])
    public = unb64(blob["tpm_public"], MAX_TPM_BLOB)
    private = unb64(blob["tpm_private"], MAX_TPM_BLOB)
    nonce = unb64(blob["nonce"], 12)
    ciphertext = unb64(blob["ciphertext"], MAX_PROFILE + 16)
    if not public or not private or len(nonce) != 12 or not 17 <= len(ciphertext) <= MAX_PROFILE + 16:
        raise SealedWifiError("invalid sealed blob")
    validate_public(public, bytes.fromhex(blob["policy_sha256"]))
    head = {key: value for key, value in blob.items() if key not in {"nonce", "ciphertext"}}
    return blob, public, private, nonce, ciphertext, canonical(head)


def unseal(raw, install_id, work):
    blob, public, private, nonce, ciphertext, aad = parse_blob(raw, install_id)
    policy, values, digest = build_policy(work, blob["pcrs"])
    if digest.hex() != blob["policy_sha256"]:
        raise SealedWifiError("TPM policy digest mismatch")
    check_live_pcrs(work, blob["pcrs"])
    primary = work / "primary.ctx"
    obj = work / "sealed.ctx"
    session = work / "policy.ctx"
    (work / "sealed.pub").write_bytes(public)
    (work / "sealed.priv").write_bytes(private)
    key = bytearray()
    try:
        tpm("createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", primary)
        tpm("load", "-C", primary, "-u", work / "sealed.pub", "-r", work / "sealed.priv", "-c", obj)
        tpm("startauthsession", "--policy-session", "-S", session)
        # The real policy session verifies the live PCRs against these exact
        # values. No auth-value or alternate branch is configured on the object.
        tpm("policypcr", "-S", session, "-l", PCR_SELECTION, "-f", values)
        key.extend(tpm("unseal", "-c", obj, "-p", f"session:{session}", secret_output=True))
        if len(key) != 32:
            raise SealedWifiError("TPM unsealed key invalid")
        try:
            profile = AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise SealedWifiError("sealed Wi-Fi authentication failed") from exc
        # Enforce the same narrowly supported NetworkManager profile after
        # decryption. No plaintext is printed or persisted outside /run.
        return normalize_profile(profile)
    finally:
        key[:] = b"\x00" * len(key)
        flush(session)
        flush(obj)
        flush(primary)


def check_denied(raw, install_id, work):
    """Factory preflight: only a real, different TPM PCR reading is expected."""
    blob, _public, _private, _nonce, _ciphertext, _aad = parse_blob(raw, install_id)
    check_live_pcrs(work, blob["pcrs"])
    raise SealedWifiError("factory boot unexpectedly matches the sealed release")


def read_root_owned(path, maximum):
    """Walk every component with O_NOFOLLOW; retain the final opened FD."""
    if not path.startswith("/"):
        raise SealedWifiError("invalid sealed blob path")
    parts = Path(path).parts[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise SealedWifiError("untrusted sealed blob directory")
        target = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(target)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                    or not 0 < before.st_size <= maximum):
                raise SealedWifiError("untrusted sealed blob")
            raw = os.read(target, maximum + 1)
            after = os.fstat(target)
            if len(raw) != before.st_size or len(raw) > maximum or (before.st_ino, before.st_mtime_ns, before.st_size) != (after.st_ino, after.st_mtime_ns, after.st_size):
                raise SealedWifiError("sealed blob changed while reading")
            return raw
        finally:
            os.close(target)
    finally:
        os.close(fd)


def open_output_parent(path, require_root):
    if not path.startswith("/"):
        raise SealedWifiError("invalid output path")
    parts = Path(path).parts[1:]
    if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
        raise SealedWifiError("invalid output path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            if require_root:
                info = os.fstat(fd)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise SealedWifiError("untrusted output directory")
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def write_exclusive(path, data, *, require_root=False):
    parent_fd, name = open_output_parent(path, require_root)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(data)
                output.flush()
                os.fsync(fd)
        except Exception:
            os.unlink(name, dir_fd=parent_fd)
            raise
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def main(argv=None):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal_args = sub.add_parser("seal")
    seal_args.add_argument("--profile-fd", type=int, required=True)
    seal_args.add_argument("--expected-pcrs", required=True)
    seal_args.add_argument("--install-id", required=True)
    seal_args.add_argument("--out", required=True)
    unseal_args = sub.add_parser("unseal")
    unseal_args.add_argument("--blob", required=True)
    unseal_args.add_argument("--out", required=True)
    check_args = sub.add_parser("check-denied")
    check_args.add_argument("--blob", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            install_id = validate_id(args.install_id)
            if not Path(args.out).is_absolute() or Path(args.out).name != HOST_BASENAME:
                raise SealedWifiError("invalid sealed blob output")
            pcrs = parse_expected(Path(args.expected_pcrs).read_bytes(), install_id)
            profile = read_profile_fd(args.profile_fd)
            with tempfile.TemporaryDirectory(prefix="darkbloom-wifi-", dir="/run") as tmp:
                result = seal(profile, pcrs, install_id, Path(tmp))
            write_exclusive(args.out, result)
        elif args.command == "unseal":
            if args.out != NETWORK_OUTPUT:
                raise SealedWifiError("invalid NetworkManager output")
            m = re.fullmatch(re.escape(HOST_PREFIX) + r"([A-Za-z0-9][A-Za-z0-9._-]{0,79})/" + HOST_BASENAME, args.blob)
            if m is None:
                raise SealedWifiError("invalid sealed blob path")
            raw = read_root_owned(args.blob, MAX_BLOB)
            with tempfile.TemporaryDirectory(prefix="darkbloom-wifi-", dir="/run/darkbloom-wifi") as tmp:
                result = unseal(raw, m.group(1), Path(tmp))
            write_exclusive(args.out, result, require_root=True)
        else:
            if not Path(args.blob).is_absolute() or Path(args.blob).name != HOST_BASENAME:
                raise SealedWifiError("invalid sealed blob path")
            raw = read_root_owned(args.blob, MAX_BLOB)
            blob = parse_canonical(raw, MAX_BLOB)
            install_id = validate_id(blob.get("install_id") if isinstance(blob, dict) else None)
            with tempfile.TemporaryDirectory(prefix="darkbloom-wifi-", dir="/run") as tmp:
                check_denied(raw, install_id, Path(tmp))
    except PcrMismatch:
        raise SystemExit(3) from None
    except (SealedWifiError, OSError):
        # Never include exception details: OS and library errors can contain
        # credential contents or private paths supplied by the caller.
        raise SystemExit("sealed Wi-Fi operation failed") from None


if __name__ == "__main__":
    main()
