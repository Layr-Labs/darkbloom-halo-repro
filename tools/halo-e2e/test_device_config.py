"""Unprivileged device-config and staging tests using temporary public pins."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest

import device_config


GOOD = {
    "v": 1,
    "hostname": "example-halo",
    "owner_user": "operator",
    "host_partuuid": "11111111-2222-4333-8444-555555555555",
    "host_root_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    "esp_mount": "/efi",
    "esp_device": "/dev/nvme1n1p2",
    "esp_partuuid": "99999999-8888-4777-8666-555555555555",
    "esp_disk": "/dev/nvme1n1",
    "esp_partition": 2,
    "factory_efi_dir": "EFI/factory-shim",
    "factory_boot_label": "Factory Secure Boot",
    "mok_cert_sha256": "a" * 64,
    "wifi_iface": "wlp8s0",
}


class DeviceConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "device.json"
        self.path.write_bytes(device_config.canonical(GOOD))

    def test_strict_canonical_config_and_scalar_cli(self):
        self.assertEqual(device_config.load(self.path), GOOD)
        cli = Path(device_config.__file__)
        result = subprocess.run([sys.executable, "-I", str(cli), "get", str(self.path), "esp_partition"],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout, "2\n")

    def test_rejects_unknown_duplicates_types_traversal_and_mismatched_device(self):
        for key, value in (("owner_user", "x ALL=(root)"), ("esp_partition", True),
                           ("esp_partition", 1), ("factory_efi_dir", "EFI/../other"),
                           ("esp_mount", "/tmp"), ("mok_cert_sha256", "A" * 64)):
            config = copy.deepcopy(GOOD)
            config[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                device_config.validate(config)
        config = copy.deepcopy(GOOD)
        config["secret_key_path"] = "/private/key"
        with self.assertRaises(ValueError):
            device_config.validate(config)
        self.path.write_text('{"v":1,"v":1}')
        with self.assertRaises(ValueError):
            device_config.load(self.path)
        self.path.write_text(json.dumps(GOOD))
        with self.assertRaises(ValueError):
            device_config.load(self.path)
        self.path.unlink()
        self.path.symlink_to("elsewhere")
        with self.assertRaises(ValueError):
            device_config.load(self.path)

    def test_generator_stages_only_public_cert_and_config_once(self):
        key, pem, der = self.root / "test.key", self.root / "test.pem", self.root / "test.der"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(pem), "-subj", "/CN=fixture"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with der.open("wb") as output:
            subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "DER"], check=True, stdout=output)
        script = Path(__file__).with_name("make-device-config.py")
        args = [sys.executable, "-I", str(script), "--out-dir", str(self.root / "stage"), "--boot-cert", str(der)]
        for key_name in GOOD.keys() - {"v", "mok_cert_sha256"}:
            args.extend(["--" + key_name.replace("_", "-"), str(GOOD[key_name])])
        subprocess.run(args, check=True, capture_output=True)
        staged = self.root / "stage/inputs"
        self.assertEqual((staged / "boot-cert.der").read_bytes(), der.read_bytes())
        self.assertEqual(device_config.load(staged / "device.json")["mok_cert_sha256"], hashlib.sha256(der.read_bytes()).hexdigest())
        self.assertEqual({p.name for p in staged.iterdir()}, {"device.json", "boot-cert.der"})
        self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
        archive = self.root / "bootstrap.tar"
        builder = Path(__file__).with_name("make-bootstrap-archive.py")
        subprocess.run([sys.executable, "-I", str(builder), "--inputs", str(staged), "--output", str(archive)],
                       check=True, capture_output=True)
        with tarfile.open(archive, "r:") as bundle:
            members = bundle.getmembers()
            self.assertEqual(len(members), 10)
            self.assertTrue(all(m.isfile() and not m.issym() for m in members))
            self.assertEqual({m.name for m in members if m.name.startswith("inputs/")},
                             {"inputs/device.json", "inputs/boot-cert.der"})
            self.assertNotIn("test.key", {m.name for m in members})


if __name__ == "__main__":
    unittest.main()
