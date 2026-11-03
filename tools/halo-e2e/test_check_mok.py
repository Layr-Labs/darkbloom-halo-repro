"""Synthetic EFI variable tests for the copied exact-DER MOK parser."""

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-mok.py")
SPEC = importlib.util.spec_from_file_location("check_mok", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CheckMokTests(unittest.TestCase):
    def test_exact_public_parser_copy_and_exact_der_presence(self):
        self.assertEqual(hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                         "6c8b97123e00e24e3d07192a7a13f80559e709745bfde51da1723dc6eaf62d20")
        cert = b"synthetic DER bytes"
        entry = b"\0" * 16 + cert
        listing = struct.pack("<16sIII", CHECKER.X509_GUID, 28 + len(entry), 0, len(entry)) + entry
        with tempfile.TemporaryDirectory() as directory:
            variable = Path(directory) / ("MokListRT-" + CHECKER.SHIM_GUID)
            variable.write_bytes(b"\x07\0\0\0" + listing)
            self.assertTrue(CHECKER.check(cert, Path(directory))["enrolled"])
            self.assertFalse(CHECKER.check(b"different DER", Path(directory))["enrolled"])
            variable.write_bytes(b"\x07\0\0\0" + listing[:-1])
            with self.assertRaises(ValueError):
                CHECKER.check(cert, Path(directory))


if __name__ == "__main__":
    unittest.main()
