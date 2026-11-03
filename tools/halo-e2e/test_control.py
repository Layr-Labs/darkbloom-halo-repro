#!/usr/bin/env python3
"""Controller tests replace hardware/system actions; only temp files are real."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import bundle
import control


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.state = self.base / "state"
        (self.state / "bundles").mkdir(parents=True)
        (self.state / "trust").mkdir()
        self.staging = self.base / "staging"
        (self.staging / "out").mkdir(parents=True)
        self.esp = self.base / "esp"
        self.esp.mkdir()
        self.patches = [patch.object(control, "STATE", self.state), patch.object(control, "staging_path", return_value=self.staging),
                        patch.object(control, "esp_path", return_value=self.esp), patch.object(control, "check_esp"),
                        patch.object(control, "verify_factory"), patch.object(control, "reconcile_order"),
                        patch.object(control, "check_bootnext", return_value=False)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.hardware = patch.object(control, "run", return_value=b"").start()
        self.addCleanup(patch.stopall)
        (self.state / "sequence.json").write_text('{"sequence":0}\n')
        rows = []
        for name in sorted(bundle.NAMES):
            data = b"release-001\n" if name == "out/install-id" else (name + "\n").encode()
            (self.staging / name).write_bytes(data)
            rows.append(dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        raw = bundle.canonical(dict(v=1, domain=bundle.DOMAIN, sequence=1, install_id="release-001", files=rows))
        (self.staging / "manifest.json").write_bytes(raw)
        private = self.base / "ephemeral-test.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with (self.state / "trust/boot-public.pem").open("wb") as output:
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout"], check=True, stdout=output, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(self.staging / "manifest.sig"), str(self.staging / "manifest.json")], check=True)

    def test_installs_verified_bytes_and_rejects_sequence_replay_before_installer(self):
        control.install()
        self.assertEqual(control.load("sequence.json")["sequence"], 1)
        self.assertEqual(control.load("current.json")["install_id"], "release-001")
        self.assertEqual((self.state / "bundles/1-release-001/out/install-id").read_bytes(), b"release-001\n")
        self.assertEqual(self.hardware.call_count, 1)
        args, kwargs = self.hardware.call_args
        self.assertEqual(args[0], ["/bin/bash", "/usr/local/libexec/darkbloom-text-e2e/install.sh", "install"])
        self.assertEqual(kwargs["extra_env"]["ID"], "release-001")
        with self.assertRaises(ValueError):
            control.install()
        self.assertEqual(self.hardware.call_count, 1)

    def test_bad_signature_never_accepts_bytes_advances_sequence_or_executes_installer(self):
        signature = self.staging / "manifest.sig"
        data = bytearray(signature.read_bytes())
        data[0] ^= 1
        signature.write_bytes(data)
        with self.assertRaises(subprocess.CalledProcessError):
            control.install()
        self.assertEqual(control.load("sequence.json")["sequence"], 0)
        self.assertEqual(list((self.state / "bundles").iterdir()), [])
        self.hardware.assert_not_called()

    def test_rejects_stub_sidecars_before_acceptance(self):
        directory = self.esp / "loader/addons"
        directory.mkdir(parents=True)
        (directory / "owner.addon.efi").write_bytes(b"unapproved")
        with self.assertRaises(ValueError):
            control.install()
        self.assertEqual(control.load("sequence.json")["sequence"], 0)
        self.hardware.assert_not_called()

    def test_preserves_unrelated_bootnext(self):
        # Exercise the unpatched implementation separately from install mocks.
        self.patches[-1].stop()
        self.hardware.return_value = b"BootNext: BEEF\n"
        with self.assertRaises(ValueError):
            control.check_bootnext()
        self.assertEqual(self.hardware.call_count, 1)


class ReconcileTests(unittest.TestCase):
    def test_factory_fallback_prefix_uses_device_pins(self):
        config = {"esp_partition": 2, "esp_partuuid": "99999999-8888-4777-8666-555555555555",
                  "factory_efi_dir": "EFI/factory-shim", "factory_boot_label": "Factory Secure Boot"}
        entries = {"BEEF": "Factory Secure Boot\tHD(2,GPT,99999999-8888-4777-8666-555555555555,0x800,0x200000)/File(\\EFI\\factory-shim\\shimx64.efi)",
                   "0001": "normal entry"}
        with patch.object(control, "device", return_value=config), \
             patch.object(control, "load", return_value={"order": ["0001"]}), \
             patch.object(control, "boot_state", side_effect=[(["BEEF", "0001"], entries), (["0001"], entries)]), \
             patch.object(control, "run", return_value=b"") as runner:
            control.reconcile_order()
            runner.assert_called_once_with(["/usr/bin/efibootmgr", "--bootorder", "0001"])
        entries["BEEF"] = entries["BEEF"].replace("factory-shim", "different-shim")
        with patch.object(control, "device", return_value=config), \
             patch.object(control, "load", return_value={"order": ["0001"]}), \
             patch.object(control, "boot_state", return_value=(["BEEF", "0001"], entries)), \
             patch.object(control, "run") as runner:
            with self.assertRaises(ValueError):
                control.reconcile_order()
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
