"""Pure, unprivileged fixture tests for the fixed boot report schema."""

import importlib.util
import json
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("boot-health.py")
SPEC = importlib.util.spec_from_file_location("boot_health", SCRIPT)
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)


class BootHealthTest(unittest.TestCase):
    def test_fixed_fields_never_echo_warning_lines(self):
        report = HEALTH.empty_report("01234567-89ab-cdef-0123-456789abcdef")
        HEALTH.add_warning(report, "amdxdna: aie2_get_dev_revision: Unknown device revision: 9 (raw fuse: 0x10170)")
        HEALTH.add_warning(report, "amdtee: failed to load firmware amdtee/773bd96f-b83f-4d52-b12dc529b13d8543.bin")
        HEALTH.add_warning(report, "CANARY PRIVATE PROMPT")
        HEALTH.add_failed_unit(report, "dbnode-engine.service")
        raw = HEALTH.encode_report(report)
        self.assertLessEqual(len(raw), HEALTH.MAX_REPORT_BYTES)
        self.assertNotIn(b"CANARY", raw)
        self.assertEqual(report["amdxdna_reported_revision"], 9)
        self.assertEqual(report["amdxdna_raw_fuse"], 0x10170)
        self.assertEqual(report["amdtee_missing_firmware"], ["amdtee/773bd96f-b83f-4d52-b12dc529b13d8543.bin"])
        self.assertEqual(report["warning_count"], 3)
        self.assertEqual(report["unknown_warning_count"], 1)
        self.assertEqual(json.loads(raw)["failed_units"], ["dbnode-engine.service"])

    def test_user_logs_and_invalid_unit_names_cannot_become_report_text(self):
        self.assertFalse(HEALTH.is_boot_system_record({"_UID": "1000", "SYSLOG_IDENTIFIER": "client", "MESSAGE": "CANARY"}))
        self.assertFalse(HEALTH.is_boot_system_record({"_UID": "1000", "SYSLOG_IDENTIFIER": "systemd-journald", "MESSAGE": "CANARY"}))
        self.assertFalse(HEALTH.is_boot_system_record({"_UID": "0", "_EXE": "/usr/local/bin/client", "SYSLOG_IDENTIFIER": "systemd-journald", "MESSAGE": "CANARY"}))
        self.assertTrue(HEALTH.is_boot_system_record({"_TRANSPORT": "kernel", "MESSAGE": "kernel warning"}))
        self.assertTrue(HEALTH.is_boot_system_record({"_PID": "1", "MESSAGE": "systemd warning"}))
        self.assertTrue(HEALTH.is_boot_system_record({"_UID": "0", "_EXE": "/usr/lib/systemd/systemd-journald", "MESSAGE": "systemd warning"}))
        report = HEALTH.empty_report("01234567-89ab-cdef-0123-456789abcdef")
        HEALTH.add_failed_unit(report, "CANARY:PRIVATE.service")
        raw = HEALTH.encode_report(report)
        self.assertNotIn(b"CANARY", raw)
        self.assertEqual(report["collection_error_count"], 1)
        self.assertEqual(report["failed_unit_count"], 1)

    def test_pre_inference_unknown_detail_is_bounded_and_opt_in(self):
        user = {"_UID": "1000", "SYSLOG_IDENTIFIER": "client", "PRIORITY": "3", "MESSAGE": "USER_CANARY_PRIVATE_PROMPT"}
        kernel = {"_TRANSPORT": "kernel", "PRIORITY": "3", "MESSAGE": "KERNEL_CANARY_DIAGNOSTIC"}
        report = HEALTH.empty_report("01234567-89ab-cdef-0123-456789abcdef")
        for record in (user, kernel):
            if HEALTH.is_boot_system_record(record):
                HEALTH.add_warning(report, record["MESSAGE"], record, details=True)
        raw = HEALTH.encode_report(report)
        self.assertEqual(report["unknown_warning_count"], 1)
        self.assertEqual(report["unknown_summaries"][0]["priority"], 3)
        self.assertEqual(report["unknown_summaries"][0]["transport"], "kernel")
        self.assertIn(b"KERNEL_CANARY_DIAGNOSTIC", raw)
        self.assertNotIn(b"USER_CANARY", raw)

        counts_only = HEALTH.empty_report("01234567-89ab-cdef-0123-456789abcdef")
        HEALTH.add_warning(counts_only, kernel["MESSAGE"], kernel, details=False)
        self.assertEqual(counts_only["unknown_summaries"], [])

    def test_sealed_unit_is_once_only(self):
        rootfs = pathlib.Path(__file__).resolve().parents[2] / "nodeos/text/rootfs"
        unit = (rootfs / "etc/systemd/system/dbnode-boot-health.service").read_text()
        saver = (rootfs / "usr/lib/darkbloom/boot-health-save.sh").read_text()
        self.assertIn("RemainAfterExit=yes", unit)
        self.assertIn("--pre-inference-details", saver)
        self.assertIn('test ! -e "$D/boot-health.json"', saver)
        self.assertIn('ln "$T" "$D/boot-health.json"', saver)

    def test_full_unknown_detail_preserves_counts_within_report_budget(self):
        report = HEALTH.empty_report("01234567-89ab-cdef-0123-456789abcdef")
        for i in range(32):
            record = {"_TRANSPORT": "kernel", "PRIORITY": "4", "_SYSTEMD_UNIT": "u" * 96}
            HEALTH.add_warning(report, f"boot warning {i} " + "x" * 256, record, details=True)
        raw = HEALTH.encode_report(report)
        self.assertLessEqual(len(raw), HEALTH.MAX_REPORT_BYTES)
        self.assertEqual(report["unknown_warning_count"], 32)
        self.assertEqual(report["warning_count"], 32)
        self.assertLessEqual(len(report["unknown_summaries"]), 32)


if __name__ == "__main__":
    unittest.main()
