"""Offline export fixtures; no mount, TPM, network, or firmware operations."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "nodeos/text/rootfs/usr/lib/darkbloom/offline-calibration.py"
SPEC = importlib.util.spec_from_file_location("offline_calibration", SCRIPT)
CAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAL)
PARTUUID = "33333333-4444-5555-6666-777777777777"
NONCE = b"a" * 64 + b"\n"
CONFIG = {"v": 1, "esp_device": "/dev/nvme4n2p3", "esp_partuuid": PARTUUID}


def evidence():
    return (json.dumps({"quoted_pcrs": CAL.PCRS, "ak_public": "0102", "attest": "0304", "signature": "0506",
                        "pcr_read_sha256": {str(pcr): "0" * 64 for pcr in CAL.PCRS},
                        "event_log": base64.b64encode(b"public-fixture-event-log").decode()}) + "\n").encode()


class OfflineCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="offline-calibration-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.request = self.base / "EFI/darkbloom-text/fixture-001/calibration"
        self.request.mkdir(parents=True)
        (self.request / "nonce").write_bytes(NONCE)

    def test_signed_esp_pin_is_unique_and_matches_verified_config(self):
        cmdline = "nodeos.esp-partuuid=" + PARTUUID
        self.assertEqual(CAL.esp_config(cmdline, json.dumps(CONFIG)), CONFIG)
        for command, config in (("quiet", CONFIG), (cmdline + " " + cmdline, CONFIG),
                                (cmdline, CONFIG | {"esp_partuuid": "0" * 36}),
                                (cmdline, CONFIG | {"esp_device": "/dev/../etc/passwd"}),
                                (cmdline, CONFIG | {"unexpected": True})):
            with self.subTest(command=command, config=config), self.assertRaises(ValueError):
                CAL.esp_config(command, json.dumps(config))

    def test_kernel_partition_identity_binds_the_allowed_block_device(self):
        metadata = self.base / "8:3"
        metadata.mkdir()
        uevent = metadata / "uevent"
        device = mock.Mock(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 3))
        with mock.patch.object(CAL.os, "stat", return_value=device):
            uevent.write_text(f"DEVTYPE=partition\nPARTUUID={PARTUUID}\n")
            CAL.pinned_partition(CONFIG["esp_device"], PARTUUID, self.base)
            with self.assertRaises(ValueError):
                CAL.pinned_partition(CONFIG["esp_device"], "other-partition", self.base)
            uevent.write_text(f"DEVTYPE=disk\nPARTUUID={PARTUUID}\n")
            with self.assertRaises(ValueError):
                CAL.pinned_partition(CONFIG["esp_device"], PARTUUID, self.base)

    def test_exact_request_rejects_extra_files_symlinks_and_bad_nonce(self):
        directory, nonce = CAL.request_directory(self.base, "fixture-001")
        os.close(directory)
        self.assertEqual(nonce, NONCE)
        extra = self.request / "unexpected"
        extra.write_bytes(b"public fixture")
        with self.assertRaises(ValueError):
            CAL.request_directory(self.base, "fixture-001")
        extra.unlink()
        (self.request / "nonce").write_bytes(b"A" * 64 + b"\n")
        with self.assertRaises(ValueError):
            CAL.request_directory(self.base, "fixture-001")
        (self.request / "nonce").unlink()
        (self.request / "nonce").symlink_to(self.base / "absent")
        with self.assertRaises(OSError):
            CAL.request_directory(self.base, "fixture-001")

    def test_no_request_directory_is_optional_but_symlink_is_not(self):
        (self.request / "nonce").unlink()
        self.request.rmdir()
        self.assertIsNone(CAL.request_directory(self.base, "fixture-001"))
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.request.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(OSError):
            CAL.request_directory(self.base, "fixture-001")

    def test_atomic_export_is_bounded_and_does_not_replace_existing_evidence(self):
        raw = evidence()
        directory, nonce = CAL.request_directory(self.base, "fixture-001")
        try:
            CAL.publish(directory, nonce, raw)
            self.assertEqual((self.request / "evidence.json").read_bytes(), raw)
            self.assertEqual(set(p.name for p in self.request.iterdir()), {"nonce", "evidence.json"})
            self.assertEqual(stat.S_IMODE((self.request / "evidence.json").stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                CAL.publish(directory, nonce, raw)
            self.assertEqual((self.request / "evidence.json").read_bytes(), raw)
        finally:
            os.close(directory)

    def test_changed_nonce_or_invalid_capture_never_writes_evidence(self):
        directory, nonce = CAL.request_directory(self.base, "fixture-001")
        try:
            (self.request / "nonce").write_bytes(b"b" * 64 + b"\n")
            with self.assertRaises(ValueError):
                CAL.publish(directory, nonce, evidence())
        finally:
            os.close(directory)
        self.assertFalse((self.request / "evidence.json").exists())
        for raw in (b"", b"x" * (CAL.MAX_EVIDENCE + 1), b'{}\n', b'{"quoted_pcrs":[],"quoted_pcrs":[]}'):
            with self.assertRaises(ValueError):
                CAL.validate_evidence(raw)

    def test_real_capture_pipe_enforces_limit_before_json_parsing(self):
        collector = self.base / "collector.py"
        collector.write_text("import sys\nsys.stdout.buffer.write(" + repr(evidence()) + ")\n")
        with mock.patch.object(CAL, "COLLECTOR", str(collector)):
            self.assertEqual(CAL.capture(NONCE), evidence())
        collector.write_text("import sys\nsys.stdout.buffer.write(b'x' * (256 * 1024 + 1))\n")
        with mock.patch.object(CAL, "COLLECTOR", str(collector)), self.assertRaises(ValueError):
            CAL.capture(NONCE)


if __name__ == "__main__":
    unittest.main()
