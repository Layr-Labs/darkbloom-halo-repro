"""Unprivileged contract tests: no sudo, TPM, EFI, or desktop calls."""

from contextlib import contextmanager
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location("halo_setup", Path(__file__).with_name("setup.py"))
setup = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = setup
spec.loader.exec_module(setup)


def raw_status(**changes):
    value = dict(ready=True, release_id="text-001", connected_wifi=True,
                 menu_ready=True, completed=False)
    value.update(changes)
    import json
    return json.dumps(value).encode()


class FakeBackend:
    def __init__(self, status):
        self.value = status
        self.finished = 0

    def status(self):
        return self.value

    def finish(self):
        self.finished += 1


class FakeUi:
    def __init__(self, answers=(True, True, True)):
        self.answers = iter(answers)
        self.questions = []
        self.infos = []
        self.errors = []
        self.busy_count = 0

    def ask(self, message, accept):
        self.questions.append((message, accept))
        return next(self.answers)

    def info(self, message):
        self.infos.append(message)

    def error(self, message):
        self.errors.append(message)

    @contextmanager
    def busy(self):
        self.busy_count += 1
        yield


class SetupTests(unittest.TestCase):
    def test_public_status_schema_rejects_forged_or_unsafe_fields(self):
        good = setup.parse_status(raw_status())
        self.assertEqual(good.release_id, "text-001")
        for raw in (
            b'{"ready":true,"ready":false,"release_id":"x","connected_wifi":true,"menu_ready":true,"completed":false}',
            raw_status(pairing_token="secret"),
            raw_status(ready=1),
            raw_status(release_id="<b>attacker</b>"),
            raw_status(release_id="../../other"),
            raw_status(release_id=""),
            b"x" * 4097,
        ):
            with self.subTest(raw=raw[:80]), self.assertRaises(setup.SetupError):
                setup.parse_status(raw)
        self.assertEqual(setup.parse_status(raw_status(ready=False, release_id="")).release_id, "")

    def test_backend_calls_only_fixed_helper_operations(self):
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout=raw_status())

        backend = setup.Backend(runner)
        self.assertEqual(backend.status().release_id, "text-001")
        backend.finish()
        self.assertEqual([call[0] for call in calls], [
            [setup.SUDO, "-n", setup.HELPER, "status"],
            [setup.SUDO, "-n", setup.HELPER, "finish"],
        ])
        self.assertTrue(all(call[1]["stdin"] == setup.subprocess.DEVNULL for call in calls))
        self.assertTrue(all(call[1]["stderr"] == setup.subprocess.DEVNULL for call in calls))

    def test_status_failure_never_reaches_finish(self):
        def runner(args, **kwargs):
            return SimpleNamespace(returncode=1, stdout=b"private error")

        ui = FakeUi((True,))
        backend = setup.Backend(runner)
        self.assertEqual(setup.run_wizard(ui, backend), 1)
        self.assertEqual(len(ui.errors), 1)
        self.assertNotIn("private error", ui.errors[0])

    def test_ready_device_requires_wifi_and_final_confirmation(self):
        backend = FakeBackend(setup.parse_status(raw_status()))
        ui = FakeUi()
        self.assertEqual(setup.run_wizard(ui, backend), 0)
        self.assertEqual(backend.finished, 1)
        self.assertEqual(ui.busy_count, 1)
        self.assertEqual(len(ui.questions), 3)
        self.assertIn("currently active", ui.questions[1][0])
        self.assertIn("text-001", ui.questions[2][0])

    def test_cancellation_and_failed_gates_never_finish(self):
        for answers in ((False,), (True, False), (True, True, False)):
            with self.subTest(answers=answers):
                backend = FakeBackend(setup.parse_status(raw_status()))
                self.assertEqual(setup.run_wizard(FakeUi(answers), backend), 0)
                self.assertEqual(backend.finished, 0)
        for changes in ({"ready": False}, {"connected_wifi": False}, {"menu_ready": False}):
            with self.subTest(changes=changes):
                backend = FakeBackend(setup.parse_status(raw_status(**changes)))
                ui = FakeUi((True,))
                self.assertEqual(setup.run_wizard(ui, backend), 1)
                self.assertEqual(backend.finished, 0)
                self.assertEqual(len(ui.errors), 1)
        backend = FakeBackend(setup.parse_status(raw_status(completed=True)))
        ui = FakeUi((True,))
        self.assertEqual(setup.run_wizard(ui, backend), 0)
        self.assertEqual(backend.finished, 0)
        self.assertEqual(len(ui.infos), 1)


if __name__ == "__main__":
    unittest.main()
