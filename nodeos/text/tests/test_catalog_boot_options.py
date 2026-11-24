"""Exercise the boot options that become part of the signed UKI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
DEVICE = {
    "v": 1,
    "hostname": "test-halo",
    "owner_user": "owner",
    "host_partuuid": "11111111-2222-4333-8444-555555555555",
    "host_root_uuid": "22222222-2222-4333-8444-555555555555",
    "esp_mount": "/efi",
    "esp_device": "/dev/nvme0n1p1",
    "esp_partuuid": "33333333-2222-4333-8444-555555555555",
    "esp_disk": "/dev/nvme0n1",
    "esp_partition": 1,
    "factory_efi_dir": "EFI/factory",
    "factory_boot_label": "Factory Secure Boot",
    "mok_cert_sha256": "e" * 64,
    "wifi_iface": "wlan0",
}


class CatalogBootOptionsTest(unittest.TestCase):
    def test_catalog_options_have_no_model_pin_and_survive_model_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            out = work / "out"
            out.mkdir()
            config = (json.dumps(DEVICE, sort_keys=True, separators=(",", ":")) + "\n").encode()
            (out / "device.json").write_bytes(config)
            (out / "root.roothash").write_text("a" * 64 + "\n")
            (out / "models.roothash").write_text("b" * 64 + "\n")
            profile = work / "build-host.sh"
            profile.write_text('uname() { case "$1" in -s) echo Linux;; -m) echo x86_64;; -r) echo fixture;; esac; }\n')

            def options(mode):
                inputs = {"device_config_sha256": hashlib.sha256(config).hexdigest(), "wifi_mode": "tpm-sealed"}
                if mode is not None:
                    inputs["model_mode"] = mode
                (out / "build-inputs.json").write_text(json.dumps(inputs))
                subprocess.run(["bash", str(ROOT / "nodeos/text/build.sh"), "options"],
                               env=os.environ | {"NODEOS_TEXT_WORK": str(work), "BASH_ENV": str(profile),
                                                 "ID": "fixture-catalog", "DEBUG": "0", "DEVLOG": "", "AGENT_ARGS": ""},
                               stdout=subprocess.DEVNULL, check=True)
                return (out / "options").read_text()

            pinned = options(None)
            self.assertIn("nodeos.modelshash=" + "b" * 64, pinned)
            self.assertIn("/fixture-catalog/models.erofs", pinned)
            catalog = options("catalog")
            self.assertIn("nodeos.model-mode=catalog", catalog)
            self.assertIn("roothash=" + "a" * 64, catalog)
            self.assertIn("nodeos.esp-partuuid=" + DEVICE["esp_partuuid"], catalog)
            self.assertFalse(any(part.startswith(("nodeos.models=", "nodeos.modelstree=", "nodeos.modelshash="))
                                 for part in catalog.split()))

            (out / "models.roothash").write_text("c" * 64 + "\n")
            self.assertEqual(catalog, options("catalog"))
