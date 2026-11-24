"""Synthetic TPM command tests for the exact-PCR Wi-Fi envelope.

These test parsing, real AES-GCM, command sequencing and fail-closed behavior.
They do not substitute for a matching-boot test against the hardware TPM.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("sealed-wifi.py")
SPEC = importlib.util.spec_from_file_location("sealed_wifi_tested", SOURCE)
wifi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wifi)


PROFILE = b"""[connection]
id=private-test
type=wifi
permissions=user:owner:;

[wifi-security]
key-mgmt=wpa-psk
psk=CANARY_WIFI_PASSPHRASE_47382
psk-flags=1
"""


class FakeTpm:
    """Models a PCR check and opaque TPM object; no development bypass in code."""

    def __init__(self, pcrs):
        self.live = wifi.raw_pcr_values(pcrs)
        self.key = None
        self.public = None
        self.calls = []

    def __call__(self, command, *args, input_bytes=None, secret_output=False):
        args = list(args)
        self.calls.append((command, args, secret_output))

        def after(flag):
            return Path(args[args.index(flag) + 1])

        if command == "pcrread":
            after("-o").write_bytes(self.live)
        elif command == "startauthsession":
            after("-S").write_bytes(b"policy" if "--policy-session" in args else b"trial")
        elif command == "policypcr":
            expected = after("-f").read_bytes()
            if after("-S").read_bytes() == b"policy" and expected != self.live:
                raise wifi.SealedWifiError("TPM policy refused")
            if "-L" in args:
                after("-L").write_bytes(hashlib.sha256(b"policy:" + expected).digest())
        elif command == "createprimary":
            after("-c").write_bytes(b"primary")
        elif command == "create":
            if input_bytes is None or len(input_bytes) != 32 or "-p" in args:
                raise AssertionError("sealed key not provided only on stdin with policy-only auth")
            self.key = input_bytes
            policy = after("-L").read_bytes()
            body = b"\x00\x08\x00\x0b" + (0x92).to_bytes(4, "big") + b"\x00\x20" + policy
            self.public = len(body).to_bytes(2, "big") + body
            after("-u").write_bytes(self.public)
            after("-r").write_bytes(b"opaque-private")
        elif command == "load":
            if after("-u").read_bytes() != self.public or after("-r").read_bytes() != b"opaque-private":
                raise wifi.SealedWifiError("load failed")
            after("-c").write_bytes(b"sealed-object")
        elif command == "unseal":
            if not secret_output or "-p" not in args or not str(args[args.index("-p") + 1]).startswith("session:"):
                raise AssertionError("unseal did not use policy session")
            if self.key is None:
                raise wifi.SealedWifiError("missing key")
            return self.key
        elif command == "flushcontext":
            after_path = Path(args[0])
            after_path.unlink(missing_ok=True)
        else:
            raise AssertionError("unexpected TPM command " + command)
        return b""


class SealedWifiTests(unittest.TestCase):
    def setUp(self):
        self.install_id = "text-demo-001"
        self.pcrs = {str(p): hashlib.sha256(f"expected-PCR-{p}".encode()).hexdigest() for p in wifi.PCRS}
        self.tpm = FakeTpm(self.pcrs)

    def test_exact_policy_encrypts_and_unseals(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(wifi, "tpm", self.tpm):
            work = Path(tmp)
            normalized = wifi.normalize_profile(PROFILE)
            blob = wifi.seal(normalized, self.pcrs, self.install_id, work)
            self.assertNotIn(b"CANARY_WIFI_PASSPHRASE", blob)
            self.assertNotIn(b"private-test", blob)
            self.assertEqual(wifi.unseal(blob, self.install_id, work), normalized)
            create = next(args for name, args, _ in self.tpm.calls if name == "create")
            self.assertIn("-L", create)
            self.assertNotIn("-p", create)
            self.assertEqual(create[create.index("-a") + 1], "fixedtpm|fixedparent|adminwithpolicy")
            self.assertTrue(any(name == "unseal" and secret for name, _, secret in self.tpm.calls))

    def test_wrong_pcr_is_specific_denial_before_unseal(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(wifi, "tpm", self.tpm):
            work = Path(tmp)
            blob = wifi.seal(wifi.normalize_profile(PROFILE), self.pcrs, self.install_id, work)
            self.tpm.live = b"\xff" * 32 + self.tpm.live[32:]
            with self.assertRaises(wifi.PcrMismatch):
                wifi.unseal(blob, self.install_id, work)
            self.assertFalse(any(name == "unseal" for name, _, _ in self.tpm.calls))
            with self.assertRaises(wifi.PcrMismatch):
                wifi.check_denied(blob, self.install_id, work)

    def test_missing_tpm_does_not_look_like_pcr_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(wifi, "tpm", side_effect=wifi.SealedWifiError("TPM absent")):
                with self.assertRaises(wifi.SealedWifiError) as caught:
                    wifi.check_live_pcrs(Path(tmp), self.pcrs)
                self.assertNotIsInstance(caught.exception, wifi.PcrMismatch)

    def test_factory_check_exit_codes_distinguish_mismatch_from_error(self):
        raw = wifi.canonical({"install_id": self.install_id})
        real_tempdir = tempfile.TemporaryDirectory
        temporary = lambda **_kwargs: real_tempdir()
        with mock.patch.object(wifi, "read_root_owned", return_value=raw), mock.patch.object(wifi.tempfile, "TemporaryDirectory", temporary):
            with mock.patch.object(wifi, "check_denied", side_effect=wifi.PcrMismatch("different")):
                with self.assertRaises(SystemExit) as denied:
                    wifi.main(["check-denied", "--blob", "/root/wifi-sealed.json"])
                self.assertEqual(denied.exception.code, 3)
            with mock.patch.object(wifi, "check_denied", side_effect=wifi.SealedWifiError("TPM unavailable")):
                with self.assertRaises(SystemExit) as error:
                    wifi.main(["check-denied", "--blob", "/root/wifi-sealed.json"])
                self.assertNotEqual(error.exception.code, 3)

    def test_tampered_ciphertext_fails_authenticated_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(wifi, "tpm", self.tpm):
            work = Path(tmp)
            original = json.loads(wifi.seal(wifi.normalize_profile(PROFILE), self.pcrs, self.install_id, work))
            cipher = bytearray(wifi.unb64(original["ciphertext"], wifi.MAX_PROFILE + 16))
            cipher[0] ^= 1
            original["ciphertext"] = wifi.b64(cipher)
            with self.assertRaises(wifi.SealedWifiError):
                wifi.unseal(wifi.canonical(original), self.install_id, work)

    def test_pcr_reference_rejects_other_release_and_noncanonical(self):
        value = {"v": 1, "bank": "sha256", "install_id": self.install_id, "pcrs": self.pcrs}
        self.assertEqual(wifi.parse_expected(wifi.canonical(value), self.install_id), self.pcrs)
        with self.assertRaises(wifi.SealedWifiError):
            wifi.parse_expected(wifi.canonical(value), "another-release")
        with self.assertRaises(wifi.SealedWifiError):
            wifi.parse_expected(json.dumps(value, indent=2).encode(), self.install_id)
        del value["pcrs"]["14"]
        with self.assertRaises(wifi.SealedWifiError):
            wifi.parse_expected(wifi.canonical(value), self.install_id)

    def test_profile_requires_inline_supported_psk(self):
        with self.assertRaises(wifi.SealedWifiError):
            wifi.normalize_profile(PROFILE.replace(b"psk=CANARY_WIFI_PASSPHRASE_47382", b"psk="))
        with self.assertRaises(wifi.SealedWifiError):
            wifi.normalize_profile(PROFILE.replace(b"key-mgmt=wpa-psk", b"key-mgmt=wpa-eap"))

    def test_existing_output_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "wifi-sealed.json"
            path.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                wifi.write_exclusive(str(path), b"new")
            self.assertEqual(path.read_bytes(), b"existing")

    def test_output_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "actual").mkdir()
            (root / "alias").symlink_to(root / "actual")
            with self.assertRaises(OSError):
                wifi.write_exclusive(str(root / "alias" / "wifi-sealed.json"), b"ciphertext")
            self.assertFalse((root / "actual" / "wifi-sealed.json").exists())


if __name__ == "__main__":
    unittest.main()
