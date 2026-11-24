#!/usr/bin/env python3
"""Unprivileged GNOME setup wizard for the protected Halo installer.

The wizard never handles Wi-Fi passwords, pairing tokens, signing keys, or
payload paths. All security decisions and changes belong to the fixed,
root-owned helper. Install this file root-owned as /usr/local/bin/darkbloom-setup.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
import re
import subprocess
import sys


HELPER = "/usr/local/sbin/darkbloom-halo-setup"
SUDO = "/usr/bin/sudo"
ZENITY = "/usr/bin/zenity"
STATUS_KEYS = frozenset({"ready", "release_id", "connected_wifi", "menu_ready", "completed"})
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")


class SetupError(Exception):
    """A failed or malformed protected setup operation; no raw output escapes."""


@dataclass(frozen=True)
class Status:
    ready: bool
    release_id: str
    connected_wifi: bool
    menu_ready: bool
    completed: bool


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate status field")
        result[key] = value
    return result


def parse_status(raw: bytes) -> Status:
    """Accept only the public, fixed schema returned by the root helper."""
    if len(raw) > 4096:
        raise SetupError("invalid setup status")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as error:
        raise SetupError("invalid setup status") from error
    if not isinstance(value, dict) or set(value) != STATUS_KEYS:
        raise SetupError("invalid setup status")
    if any(type(value[name]) is not bool for name in STATUS_KEYS - {"release_id"}):
        raise SetupError("invalid setup status")
    release = value["release_id"]
    if not isinstance(release, str) or (release and not RELEASE_ID.fullmatch(release)):
        raise SetupError("invalid setup status")
    if value["ready"] and not release:
        raise SetupError("invalid setup status")
    return Status(**value)


class Backend:
    """Only two fixed commands; no arguments originate in GUI or status JSON."""

    def __init__(self, runner=subprocess.run):
        self.runner = runner

    def status(self) -> Status:
        try:
            result = self.runner([SUDO, "-n", HELPER, "status"], check=False,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SetupError("protected setup status unavailable") from error
        if result.returncode != 0:
            raise SetupError("protected setup status unavailable")
        return parse_status(result.stdout)

    def finish(self) -> None:
        # The helper owns its transaction and reboot. Do not interrupt a
        # partially completed firmware or credential update on a GUI timer.
        try:
            result = self.runner([SUDO, "-n", HELPER, "finish"], check=False,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        except OSError as error:
            raise SetupError("protected setup could not finish") from error
        if result.returncode != 0:
            raise SetupError("protected setup could not finish")


class Zenity:
    def __init__(self, runner=subprocess.run, popen=subprocess.Popen):
        self.runner = runner
        self.popen = popen

    def _dialog(self, kind: str, message: str, *extra: str) -> int:
        try:
            result = self.runner([ZENITY, kind, "--title=Darkbloom Setup",
                                  "--width=480", "--text=" + message, *extra],
                                 check=False, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error:
            raise SetupError("desktop dialog unavailable") from error
        return result.returncode

    def ask(self, message: str, accept: str) -> bool:
        answer = self._dialog("--question", message,
                              "--ok-label=" + accept, "--cancel-label=Not now")
        if answer not in (0, 1):
            raise SetupError("desktop dialog unavailable")
        return answer == 0

    def info(self, message: str) -> None:
        self._dialog("--info", message)

    def error(self, message: str) -> None:
        self._dialog("--error", message)

    @contextmanager
    def busy(self):
        try:
            progress = self.popen(
                [ZENITY, "--progress", "--pulsate", "--no-cancel",
                 "--title=Darkbloom Setup", "--width=480",
                 "--text=Finishing protected setup. The computer may restart."],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise SetupError("desktop dialog unavailable") from error
        try:
            yield
        finally:
            if progress.poll() is None:
                progress.terminate()
                try:
                    progress.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    progress.kill()
                    progress.wait()
            if progress.stdin is not None:
                progress.stdin.close()


def run_wizard(ui, backend) -> int:
    if not ui.ask("Set up the prepared Darkbloom text demo on this AMD computer? It uses a test account and local coordinator. The factory AMD OS remains the default boot choice.", "Check device"):
        return 0
    try:
        status = backend.status()
    except SetupError:
        ui.error("Protected setup is unavailable. Open Darkbloom Setup again after installation is prepared.")
        return 1
    if status.completed:
        ui.info("Darkbloom is already set up. Choose AMD OS or Darkbloom OS from the boot menu at power-on.")
        return 0
    if not status.connected_wifi:
        ui.error("Connect to Wi-Fi in the factory AMD OS, then open Darkbloom Setup again.")
        return 1
    if not status.ready or not status.menu_ready:
        ui.error("The approved Darkbloom release or boot menu is not ready yet. Open Darkbloom Setup again after preparation.")
        return 1
    if not ui.ask("Use the Wi-Fi connection currently active in AMD OS? Its saved settings will be sealed by protected setup; this wizard never shows or asks for the password.", "Use current Wi-Fi"):
        return 0
    if not ui.ask("Finish setting up reviewed release " + status.release_id + " and restart once into Darkbloom OS? AMD OS stays the default, and the boot menu will offer both choices later.", "Finish setup and restart"):
        return 0
    try:
        with ui.busy():
            backend.finish()
    except SetupError:
        ui.error("Setup could not be confirmed. Reopen this wizard to check the device before trying again.")
        return 1
    return 0


def main() -> int:
    if os.geteuid() == 0:
        print("Open Darkbloom Setup as the desktop user, not as root.", file=sys.stderr)
        return 1
    if not os.access(ZENITY, os.X_OK) or not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")):
        print("Darkbloom Setup needs a signed-in GNOME desktop with Zenity.", file=sys.stderr)
        return 1
    try:
        return run_wizard(Zenity(), Backend())
    except SetupError:
        print("Darkbloom Setup could not open its desktop dialog.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
