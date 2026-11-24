#!/usr/bin/env python3
"""Host-only tests: temporary files and test RSA key, never TPM/EFI/sudo."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import bundle


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.staging = self.base / "staging"
        (self.staging / "out").mkdir(parents=True)
        rows = []
        for name in sorted(bundle.NAMES):
            data = b"release-001\n" if name == "out/install-id" else (name + "\n").encode()
            (self.staging / name).write_bytes(data)
            rows.append(dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        self.manifest = dict(v=1, domain=bundle.DOMAIN, sequence=1, install_id="release-001", files=rows)

    def copy(self, manifest=None):
        target = self.base / "accepted"
        target.mkdir(mode=0o700)
        fd = bundle.open_dir(self.staging)
        try:
            bundle.copy_payload(fd, manifest or self.manifest, target)
        finally:
            os.close(fd)
        return target

    def test_accepts_canonical_complete_data_only_bundle(self):
        parsed = bundle.parse_manifest(bundle.canonical(self.manifest))
        accepted = self.copy(parsed)
        self.assertEqual((accepted / "out/install-id").read_bytes(), b"release-001\n")
        self.assertEqual((accepted / "out/root.erofs").stat().st_mode & 0o777, 0o600)

    def test_rejects_schema_domain_boolean_sequence_and_unknown_paths(self):
        for key, value in (("domain", "other"), ("sequence", True), ("sequence", 0), ("extra", 1)):
            m = copy.deepcopy(self.manifest)
            m[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                bundle.parse_manifest(bundle.canonical(m))
        for name in ("../install.sh", "out/install.sh", "out/../root.erofs"):
            m = copy.deepcopy(self.manifest)
            m["files"][0]["name"] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.parse_manifest(bundle.canonical(m))

    def test_rejects_noncanonical_duplicate_keys_and_duplicate_names(self):
        for raw in (json.dumps(self.manifest).encode(), b'{"v":1,"v":1}', bundle.canonical(self.manifest).rstrip()):
            with self.assertRaises(ValueError):
                bundle.parse_manifest(raw)
        m = copy.deepcopy(self.manifest)
        m["files"][-1] = m["files"][0]
        with self.assertRaises(ValueError):
            bundle.parse_manifest(bundle.canonical(m))

    def test_rejects_source_file_symlink(self):
        source = self.staging / "out/root.erofs"
        source.unlink()
        source.symlink_to("install-id")
        with self.assertRaises(OSError):
            self.copy()

    def test_rejects_source_directory_symlink(self):
        (self.staging / "out").rename(self.staging / "elsewhere")
        (self.staging / "out").symlink_to("elsewhere")
        with self.assertRaises(OSError):
            self.copy()

    def test_rejects_same_size_payload_mutation(self):
        source = self.staging / "out/root.erofs"
        source.write_bytes(b"x" * source.stat().st_size)
        with self.assertRaises(ValueError):
            self.copy()

    def test_rejects_install_id_binding_mismatch(self):
        m = copy.deepcopy(self.manifest)
        m["install_id"] = "another-id"
        with self.assertRaises(ValueError):
            self.copy(m)

    def test_verifies_test_key_signature_and_rejects_modified_bytes(self):
        private, public = self.base / "test.key", self.base / "test.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with public.open("wb") as output:
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout"], check=True, stdout=output, stderr=subprocess.DEVNULL)
        raw = bundle.canonical(self.manifest)
        manifest, signature = self.base / "manifest.json", self.base / "manifest.sig"
        manifest.write_bytes(raw)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(manifest)], check=True)
        verification = self.base / "verify"
        verification.mkdir()
        bundle.verify_signature(raw, signature.read_bytes(), public, verification)
        with self.assertRaises(subprocess.CalledProcessError):
            bundle.verify_signature(raw + b" ", signature.read_bytes(), public, verification)


if __name__ == "__main__":
    unittest.main()
