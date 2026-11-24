"""Check one-time boot scheduling without reading or writing firmware variables."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import call, patch


spec = importlib.util.spec_from_file_location("wizard_admin", Path(__file__).with_name("wizard-admin.py"))
wizard = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", sys.path.copy()):
    spec.loader.exec_module(wizard)


class WizardBootTests(unittest.TestCase):
    def setUp(self):
        self.esp = Path("/efi")

    def test_oneshot_counts_down_without_a_keypress(self):
        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(wizard, "bootctl") as bootctl,
            patch.object(wizard, "run") as run,
        ):
            wizard.reboot_into_entry(self.esp)

        self.assertEqual(bootctl.call_args_list, [
            call(self.esp, "set-oneshot", wizard.ENTRY_ID),
            call(self.esp, "set-timeout-oneshot", "1"),
        ])
        self.assertEqual(run.call_args_list, [call("/usr/bin/sync"), call("/usr/bin/systemctl", "reboot")])

    def test_failed_reboot_clears_both_oneshot_overrides(self):
        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(wizard, "bootctl") as bootctl,
            patch.object(wizard, "run", side_effect=[b"", RuntimeError()]),
        ):
            with self.assertRaises(RuntimeError):
                wizard.reboot_into_entry(self.esp)

        self.assertEqual(bootctl.call_args_list[-2:], [
            call(self.esp, "set-oneshot", ""),
            call(self.esp, "set-timeout-oneshot", ""),
        ])
