#!/usr/bin/env python3
"""Mac-side, private-state runner for the real-TPM text UKI POC.

This runner never approves a release automatically. A calibration capture
authenticates a TPM proof; the operator must still review the built image
and sign its production manifest. No development roots or tiers are enabled.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
STATE = REPO / ".halo-e2e"
BIN = REPO / "poc-rs/target/debug"
PORT = 8790


def run(tool, *args):
    result = subprocess.run([str(BIN / tool), *map(str, args)], check=False)
    if result.returncode:
        # argv contains the private pairing/API token; never print it.
        raise RuntimeError(f"{tool} exited with status {result.returncode}")


def private_write(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)


def settings():
    return json.loads((STATE / "settings.json").read_text())


def initialize(lan_ip):
    ip = ipaddress.ip_address(lan_ip)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_unspecified:
        raise ValueError("provide this Mac's private LAN IPv4 address")
    for name in ("keys", "releases", "coord", "captures", "tls", "outputs", "evidence"):
        (STATE / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    for name in ("provider-token", "consumer-key"):
        path = STATE / name
        if not path.exists():
            private_write(path, (secrets.token_hex(32) + "\n").encode())
    config = STATE / "settings.json"
    expected = {"v": 1, "lan_ip": str(ip), "port": PORT, "svn": 1}
    if config.exists():
        actual = json.loads(config.read_text())
        # Keep a security-version floor raised by later approved releases.
        if (any(actual.get(k) != expected[k] for k in ("v", "lan_ip", "port"))
                or set(actual) != set(expected)
                or type(actual.get("svn")) is not int or actual["svn"] < 1):
            raise ValueError("existing LAN/TLS settings differ; review them before changing the image")
    if not config.exists():
        private_write(config, (json.dumps(expected, indent=2) + "\n").encode())
    if not (STATE / "keys/release.key").exists():
        run("dbrelease", "keygen", "-out", STATE / "keys/release")
    if not (STATE / "tls/server.pem").exists():
        run("dbcoord", "devcert", "-out", STATE / "tls", "-hosts", f"127.0.0.1,localhost,{ip}")
    print(f"Private POC state ready: {STATE}")
    print(f"Worker endpoint: wss://{ip}:{PORT}/v1/provider/ws")


def coordinator(capture):
    cfg = settings()
    args = [str(BIN / "dbcoord"), "-listen", f"0.0.0.0:{cfg['port']}",
            "-state", str(STATE / "coord"), "-pluton-certs", str(REPO / "certs/amd-pluton"),
            "-releases", str(STATE / "releases"), "-release-pub", str(STATE / "keys/release.pub"),
            "-min-svn", str(cfg["svn"]), "-boot-profile", "uki",
            "-provider-token", (STATE / "provider-token").read_text().strip() + "=acct-halo-text-poc",
            "-consumer-key", (STATE / "consumer-key").read_text().strip(),
            "-tls-cert", str(STATE / "tls/server.pem"), "-tls-key", str(STATE / "tls/server.key"),
            "-challenge", "20s", "-lease", "60s"]
    if capture:
        args.extend(["-capture-attestation", str(STATE / "captures")])
    os.execv(args[0], args)


def client(args):
    cfg = settings()
    if args[:1] == ["--"]:
        args = args[1:]
    if not args or args[0] not in ("providers", "verify", "text"):
        raise ValueError("client expects providers, verify PROVIDER, or text -prompt-file FILE -out FILE")
    run("dbclient", "-coordinator", f"https://127.0.0.1:{cfg['port']}",
        "-ca-cert", STATE / "tls/ca.pem", "-key", (STATE / "consumer-key").read_text().strip(),
        "-pluton-certs", REPO / "certs/amd-pluton", "-release-pub", STATE / "keys/release.pub",
        "-log-pub", STATE / "coord/release-log.pub", "-min-svn", cfg["svn"], *args)


def extract_capture(path, output):
    data = json.loads(path.read_bytes())
    if (data.get("schema") != "darkbloom-amd/attestation-capture/v1"
            or data.get("pre_release_verified") is not True
            or data.get("ak_activated") is not True
            or 11 not in data.get("expected_pcrs", [])):
        raise ValueError("not a hardware-authenticated UKI calibration capture")
    raw = base64.b64decode(data["evidence"]["event_log"], validate=True)
    if not raw or len(raw) > 8 * 1024 * 1024:
        raise ValueError("invalid event log size")
    private_write(output, raw)
    print(f"Extracted reference log to {output}; release_admitted={data['release_admitted']}")
    print("Review the image and compare its derived measurements before signing a release.")


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--lan-ip", required=True)
    coord = sub.add_parser("coord")
    coord.add_argument("--capture", action="store_true")
    consumer = sub.add_parser("client")
    consumer.add_argument("args", nargs=argparse.REMAINDER)
    extract = sub.add_parser("extract-capture")
    extract.add_argument("capture", type=Path)
    extract.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    if a.command == "init":
        initialize(a.lan_ip)
    elif a.command == "coord":
        coordinator(a.capture)
    elif a.command == "client":
        client(a.args)
    else:
        extract_capture(a.capture, a.out)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError) as error:
        print(f"halo-text: {error}", file=sys.stderr)
        sys.exit(1)
