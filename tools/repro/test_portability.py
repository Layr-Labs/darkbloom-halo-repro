"""Unprivileged public-interface fixtures. Never runs an installer transaction.

The installer fixture executes its real initialization in a temporary path with
identity/stat mocked; this catches Bash 3 errexit differences without root.
Signing tests use freshly generated temporary keys and stop before Docker.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repro_device", ROOT / "tools/halo-e2e/device_config.py")
DEVICE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEVICE)
GOOD = dict(v=1, hostname="fixture-halo", owner_user="operator",
            host_partuuid="11111111-2222-3333-4444-555555555555",
            host_root_uuid="22222222-3333-4444-5555-666666666666",
            esp_mount="/boot/efi", esp_device="/dev/nvme4n2p3",
            esp_partuuid="33333333-4444-5555-6666-777777777777",
            esp_disk="/dev/nvme4n2", esp_partition=3, factory_efi_dir="EFI/vendor",
            factory_boot_label="Vendor Boot", mok_cert_sha256="a" * 64, wifi_iface="wlan0")


class PortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="halo-repro-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.envfile = self.base / "environment.sh"
        self.envfile.write_text("python3() { " + shlex.quote(sys.executable) + ' "$@"; }\n')
        self.env = os.environ | {"BASH_ENV": str(self.envfile)}

    def run_bash(self, path, *args, env=None):
        return subprocess.run(["bash", str(path), *args], env=env or self.env,
                              text=True, capture_output=True)

    def test_options_use_explicit_snapshot_and_reject_drift(self):
        work = self.base / "work"
        out = work / "out"
        out.mkdir(parents=True)
        config = out / "device.json"
        config.write_bytes(DEVICE.canonical(GOOD))
        (out / "root.roothash").write_text("b" * 64 + "\n")
        (out / "models.roothash").write_text("c" * 64 + "\n")
        (out / "build-inputs.json").write_text(json.dumps({"device_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest()}))
        with self.envfile.open("a") as f:
            f.write('uname() { case "$1" in -s) echo Linux;; -m) echo x86_64;; -r) echo fixture-kernel;; esac; }\n')
            f.write('sha256sum() { python3 -c \'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())\' "$1"; }\n')
        env = self.env | {"NODEOS_TEXT_WORK": str(work), "ID": "fixture-v1"}
        script = ROOT / "nodeos/text/build.sh"
        result = self.run_bash(script, "options", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        options = (out / "options").read_text()
        self.assertIn("nodeos.host-partuuid=" + GOOD["host_partuuid"], options)
        self.assertIn("nodeos.host-uuid=" + GOOD["host_root_uuid"], options)
        config.write_bytes(DEVICE.canonical(GOOD | {"hostname": "changed-host"}))
        self.assertNotEqual(self.run_bash(script, "options", env=env).returncode, 0)
        config.unlink()
        self.assertNotEqual(self.run_bash(script, "options", env=env).returncode, 0)

    def test_init_rejects_missing_or_ambiguous_partition_metadata(self):
        source = (ROOT / "nodeos/text/init").read_text()
        function = "find_partition() {" + source.split("find_partition() {", 1)[1].split("\n}", 1)[0] + "\n}"
        sysfs = self.base / "sysfs"
        sysfs.mkdir()
        def probe():
            return subprocess.run(["sh", "-c", function + '\nfind_partition "$1" "$2"',
                                   "fixture", str(sysfs), GOOD["host_partuuid"]], text=True, capture_output=True)
        self.assertEqual(probe().returncode, 1)
        (sysfs / "dev9").mkdir()
        (sysfs / "dev9/uevent").write_text("PARTUUID=" + GOOD["host_partuuid"] + "\n")
        result = probe()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "dev9"))
        (sysfs / "dev10").mkdir()
        (sysfs / "dev10/uevent").write_text("PARTUUID=" + GOOD["host_partuuid"] + "\n")
        self.assertEqual(probe().returncode, 2)

    def test_installer_config_fields_and_writable_path_guards(self):
        state = self.base / "state"
        bundle = state / "bundles/release"
        (bundle / "out").mkdir(parents=True)
        (bundle / "out/install-id").write_text("fixture-v1\n")
        config = state / "device.json"
        config.write_bytes(DEVICE.canonical(GOOD))
        config.chmod(0o600)
        header = (ROOT / "nodeos/text/install.sh").read_text().split('case "${1:-install}" in', 1)[0]
        header = header.replace("/usr/local/libexec/darkbloom-text-e2e", str(ROOT / "tools/halo-e2e"))
        header = header.replace("/var/lib/darkbloom-text-e2e", str(state))
        header += '\nprintf "%s|%s|%s|%s\\n" "$ESP" "$ESP_DEVICE" "$ESP_DISK" "$ESP_PARTITION"\n'
        script = self.base / "installer-initialization.sh"
        script.write_text(header)
        with self.envfile.open("a") as f:
            f.write('''id() { echo 0; }
hostname() { echo fixture-halo; }
readlink() { python3 -c 'import pathlib,sys;print(pathlib.Path(sys.argv[1]).resolve())' "$2"; }
stat() { if [ "$2" = %u ]; then echo 0; else python3 -c 'import pathlib,sys;print(oct(pathlib.Path(sys.argv[1]).stat().st_mode&0o777)[2:])' "$3"; fi; }
''')
        env = self.env | {"NODEOS_TEXT_WORK": str(bundle)}
        result = self.run_bash(script, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/boot/efi|/dev/nvme4n2p3|/dev/nvme4n2|3")
        config.chmod(0o666)
        self.assertNotEqual(self.run_bash(script, env=env).returncode, 0)
        config.chmod(0o600)
        bundle.chmod(0o777)
        self.assertNotEqual(self.run_bash(script, env=env).returncode, 0)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_signer_requires_explicit_pin_and_matching_key_before_docker(self):
        cert, key, wrong = (self.base / n for n in ("test.pem", "test.key", "wrong.key"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=repro-fixture/", "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(wrong)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
        pin = hashlib.sha256(der).hexdigest()
        unsigned = self.base / "unsigned.efi"
        unsigned.write_bytes(b"fixture")
        script = ROOT / "poc-rs/scripts/sign-text-uki.sh"
        args = ["--unsigned", str(unsigned), "--out", str(self.base / "signed"), "--cert", str(cert), "--key", str(key)]
        self.assertNotEqual(self.run_bash(script).returncode, 0)
        self.assertNotEqual(self.run_bash(script, *args).returncode, 0)
        self.assertIn("fingerprint", self.run_bash(script, *args, "--cert-sha256", "0" * 64).stderr)
        mismatched = [str(wrong) if a == str(key) else a for a in args]
        self.assertIn("does not match", self.run_bash(script, *mismatched, "--cert-sha256", pin).stderr)
        fakebin = self.base / "bin"
        fakebin.mkdir()
        trace = self.base / "docker.trace"
        docker = fakebin / "docker"
        docker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$TRACE"\n[ "$1" = image ] && exit 0\nexit 42\n')
        docker.chmod(0o755)
        env = self.env | {"PATH": str(fakebin) + ":" + os.environ["PATH"], "TRACE": str(trace)}
        result = self.run_bash(script, *args, "--cert-sha256", pin.upper(), env=env)
        self.assertEqual(result.returncode, 42)
        self.assertIn("--cert-sha256\n" + pin, trace.read_text())
        self.assertFalse((self.base / "signed").exists())


if __name__ == "__main__":
    unittest.main()
