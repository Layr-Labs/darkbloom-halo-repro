"""Runtime handoff fixtures: temporary files and a mocked TPM decryptor only."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "nodeos/text/rootfs/usr/lib/darkbloom/sealed-wifi-start.py"
SPEC = importlib.util.spec_from_file_location("sealed_wifi_runtime", SCRIPT)
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)
CMDLINE = "quiet nodeos.root=/var/lib/darkbloom-text-nodeos/fixture-001/root.erofs lockdown=confidentiality"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-wifi-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.host = self.base / "host"
        self.data = self.host / "var/lib/darkbloom-text-nodeos/fixture-001"
        self.data.mkdir(parents=True)
        self.blob = self.data / "wifi-sealed.json"
        self.output = self.base / "run/NetworkManager/system-connections/darkbloom-wifi.nmconnection"
        # Fixtures run as the ordinary Mac/Linux user, never as root. Real
        # nofollow opens and permission checks remain active; only UID is mapped.
        original = RUNTIME.protected
        def own_fixture(info):
            original(SimpleNamespace(st_uid=0, st_mode=info.st_mode))
        self.guard = mock.patch.object(RUNTIME, "protected", side_effect=own_fixture)
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def start(self):
        # /private/tmp is intentionally writable on macOS. Start traversal from
        # the private fixture parent, keeping the actual output-parent logic.
        real_prepare = RUNTIME.prepare_output
        def prepare(output):
            with mock.patch.object(RUNTIME, "protected"):
                real_prepare(output)
        with mock.patch.object(RUNTIME, "prepare_output", side_effect=prepare):
            return RUNTIME.start(CMDLINE, self.host, self.output)

    def test_signed_root_path_is_unique_and_bounded(self):
        self.assertEqual(RUNTIME.install_id(CMDLINE), "fixture-001")
        for bad in ("quiet", CMDLINE + " " + CMDLINE,
                    "nodeos.root=/var/lib/darkbloom-text-nodeos/../root.erofs",
                    "nodeos.root=/elsewhere/fixture/root.erofs",
                    "nodeos.root=/var/lib/darkbloom-text-nodeos/" + "a" * 81 + "/root.erofs"):
            with self.subTest(cmdline=bad), self.assertRaises(ValueError):
                RUNTIME.install_id(bad)

    def test_absent_blob_allows_calibration_and_removes_old_output(self):
        self.output.parent.mkdir(parents=True)
        self.output.write_bytes(b"old private fixture")
        with mock.patch.object(RUNTIME.subprocess, "run") as run:
            self.assertFalse(self.start())
            run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_missing_blob_runs_only_fixed_offline_export_then_blocks_network(self):
        with mock.patch.object(RUNTIME.os, "geteuid", return_value=0), \
             mock.patch.object(RUNTIME.sys, "argv", [str(SCRIPT)]), \
             mock.patch.object(RUNTIME, "STATUS", self.base / "status.json"), \
             mock.patch.object(RUNTIME.Path, "read_text", return_value=CMDLINE), \
             mock.patch.object(RUNTIME, "start", return_value=False), \
             mock.patch.object(RUNTIME, "save_status") as status, \
             mock.patch.object(RUNTIME.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                RUNTIME.main()
        status.assert_called_once_with(False)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "start", "darkbloom-offline-calibration.service"])

    def test_present_bad_or_symlinked_objects_never_become_calibration(self):
        for kind in ("empty", "oversize", "directory", "dangling-symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    self.blob.mkdir()
                elif kind == "dangling-symlink":
                    self.blob.symlink_to(self.data / "absent")
                else:
                    self.blob.write_bytes(b"" if kind == "empty" else b"x" * (128 * 1024 + 1))
                with mock.patch.object(RUNTIME.subprocess, "run") as run:
                    with self.assertRaises((ValueError, OSError)):
                        self.start()
                    run.assert_not_called()
                if self.blob.is_dir():
                    self.blob.rmdir()
                else:
                    self.blob.unlink()

    def test_symlinked_release_directory_is_rejected(self):
        self.data.rmdir()
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.data.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(OSError):
            self.start()

    def test_symlinked_runtime_directory_is_rejected(self):
        self.output.parent.parent.mkdir(parents=True)
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.output.parent.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(OSError):
            self.start()

    def test_success_uses_fixed_decryptor_and_private_output(self):
        self.blob.write_bytes(b"ciphertext fixture")
        def decrypt(*args, **kwargs):
            self.output.write_bytes(b"[connection]\nid=synthetic-fixture\n")
            self.output.chmod(0o600)
        with mock.patch.object(RUNTIME.subprocess, "run", side_effect=decrypt) as run:
            self.assertTrue(self.start())
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/bin/python3", "-I", "-B", RUNTIME.UNSEAL,
                                "--blob", str(self.blob), "--out", str(self.output)])
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.output.parent.stat().st_mode), 0o700)

    def test_decrypt_error_or_wrong_mode_removes_partial_plaintext(self):
        self.blob.write_bytes(b"ciphertext fixture")
        for failure in ("decrypt", "mode"):
            with self.subTest(failure=failure):
                def decrypt(*args, **kwargs):
                    self.output.write_bytes(b"private fixture must disappear")
                    self.output.chmod(0o644)
                    if failure == "decrypt":
                        raise subprocess.CalledProcessError(1, args[0], stderr=b"private fixture")
                with mock.patch.object(RUNTIME.subprocess, "run", side_effect=decrypt):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        self.start()
                self.assertFalse(self.output.exists())

    def test_status_contains_only_public_availability(self):
        status = self.base / "status.json"
        with mock.patch.object(RUNTIME, "STATUS", status), mock.patch.object(RUNTIME.sys, "stdout") as stdout:
            RUNTIME.save_status(True)
        self.assertEqual(json.loads(status.read_text()), {"v": 1, "sealed_wifi_available": True})
        self.assertEqual(stat.S_IMODE(status.stat().st_mode), 0o644)
        self.assertEqual(stdout.write.call_args.args[0], status.read_text())


class BuildModeTests(unittest.TestCase):
    def test_root_ownership_and_write_protection_are_required(self):
        RUNTIME.protected(SimpleNamespace(st_uid=0, st_mode=0o100600))
        for uid, mode in ((501, 0o100600), (0, 0o100620), (0, 0o100602)):
            with self.subTest(uid=uid, mode=mode), self.assertRaises(ValueError):
                RUNTIME.protected(SimpleNamespace(st_uid=uid, st_mode=mode))

    def test_real_staging_branch_omits_plaintext_and_keeps_embedded_flow(self):
        source = (ROOT / "nodeos/text/build.sh").read_text()
        marker = '    if [[ $WIFI_MODE == embedded ]]; then\n'
        block = marker + source.split(marker, 1)[1].split('    cat >"$B/generated/usr/share/darkbloom/agent.env"', 1)[0]
        with tempfile.TemporaryDirectory(prefix="sealed-wifi-staging-") as temporary:
            base = Path(temporary).resolve()
            profile = base / "fixture.nmconnection"
            profile.write_text('[connection]\nid=synthetic-fixture\ntype=wifi\n[wifi-security]\nkey-mgmt=wpa-psk\npsk=synthetic-test-only-psk\n')
            workflow = base / "workflow.json"
            workflow.write_text('{}\n')
            for mode in ("embedded", "tpm-sealed"):
                build = base / mode
                connections = build / "secrets/etc/NetworkManager/system-connections"
                connections.mkdir(parents=True)
                (build / "generated/usr/share/darkbloom").mkdir(parents=True)
                env = os.environ | {"B": str(build), "PROJECT": str(ROOT), "WIFI_MODE": mode,
                                    "WIFI_PROFILE": str(profile), "TEXT_WORKFLOW": str(workflow), "OUT": str(base)}
                dependency = 'device_get() { case "$2" in esp_device) echo /dev/nvme4n2p3;; esp_partuuid) echo 33333333-4444-5555-6666-777777777777;; esac; }\n'
                result = subprocess.run(["bash", "-eu", "-c", dependency + block], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                if mode == "embedded":
                    copied = connections / "nodeos.nmconnection"
                    self.assertIn("psk-flags=0", copied.read_text())
                    self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
                else:
                    self.assertEqual(list(connections.iterdir()), [])
                    dropin = build / "generated/etc/systemd/system/NetworkManager.service.d/20-darkbloom-sealed-wifi.conf"
                    self.assertIn("Requires=darkbloom-sealed-wifi.service", dropin.read_text())
                    self.assertIn("After=darkbloom-sealed-wifi.service", dropin.read_text())
                    for unit in ("dbnode-engine", "dbnode-llama", "dbnode"):
                        gate = build / f"generated/etc/systemd/system/{unit}.service.d/20-darkbloom-sealed-wifi.conf"
                        self.assertEqual(gate.read_text(), dropin.read_text())
                    for path in build.rglob('*'):
                        if path.is_file():
                            self.assertNotIn(b"synthetic-test-only-psk", path.read_bytes())

    def test_prepare_refuses_plaintext_in_sealed_mode_and_keeps_embedded_default(self):
        with tempfile.TemporaryDirectory(prefix="sealed-wifi-build-") as temporary:
            base = Path(temporary)
            envfile = base / "environment.sh"
            envfile.write_text('uname() { case "$1" in -s) echo Linux;; -m) echo x86_64;; -r) echo fixture;; esac; }\n')
            env = os.environ | {"BASH_ENV": str(envfile), "NODEOS_TEXT_WORK": str(base / "work")}
            for key in ("WIFI_MODE", "WIFI_PROFILE", "AGENT"):
                env.pop(key, None)
            def run(extra):
                return subprocess.run(["bash", str(ROOT / "nodeos/text/build.sh"), "prepare"],
                                      env=env | extra, capture_output=True, text=True)
            default = run({})
            self.assertNotEqual(default.returncode, 0)
            self.assertIn("WIFI_PROFILE", default.stderr)
            sealed = run({"WIFI_MODE": "tpm-sealed", "WIFI_PROFILE": "/private/do-not-copy"})
            self.assertNotEqual(sealed.returncode, 0)
            self.assertIn("WIFI_PROFILE is forbidden", sealed.stderr)
            invalid = run({"WIFI_MODE": "unknown"})
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("WIFI_MODE must be", invalid.stderr)
            no_plaintext = run({"WIFI_MODE": "tpm-sealed"})
            self.assertNotEqual(no_plaintext.returncode, 0)
            self.assertIn("AGENT", no_plaintext.stderr)
            self.assertNotIn("WIFI_PROFILE", no_plaintext.stderr)


if __name__ == "__main__":
    unittest.main()
