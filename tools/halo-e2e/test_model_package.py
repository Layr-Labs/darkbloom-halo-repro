"""Synthetic package tests; no model weights, TPM, or network are used."""

import importlib.util
import fcntl
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MODULE = Path(__file__).with_name("model-package.py")
SPEC = importlib.util.spec_from_file_location("model_package", MODULE)
mp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mp)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="model-package-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.package = self.root / "unpublished"
        self.package.mkdir()
        (self.package / "model.erofs").write_bytes(b"synthetic erofs image\n")
        (self.package / "model.verity").write_bytes(b"synthetic verity tree\n")
        self.weights = self.root / "model.gguf"
        self.weights.write_bytes(b"GGUF synthetic model\n")
        self.workflow = self.root / "workflow.json"
        self.workflow.write_bytes(b'{"id":"fixture"}\n')
        private = Ed25519PrivateKey.generate()
        self.private = self.root / "signing.pem"
        self.public = self.root / "trusted.pem"
        self.private.write_bytes(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.public.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.library = self.root / "home/owner/.local/share/darkbloom/models"

    def create(self):
        return mp.create(SimpleNamespace(
            package=str(self.package), weights=str(self.weights), workflow=str(self.workflow),
            model_id="test-model", engine_version="1:0.2.0+dfsg1-1+rex2bvdebian13.1",
            verity_root="a" * 64, security_version=2, private_key=str(self.private)))

    def stage(self):
        return mp.stage(SimpleNamespace(package=str(self.package), library=str(self.library),
                                        public_key=str(self.public)))

    def select(self, digest):
        mp.select(SimpleNamespace(digest=digest, library=str(self.library), public_key=str(self.public)))

    def test_create_stage_select_and_held_descriptors(self):
        digest = self.create()
        self.assertEqual(digest, self.stage())
        self.assertEqual(digest, self.stage())
        self.select(digest)
        with mp.open_package(self.library, self.public) as pkg:
            self.assertEqual(pkg.digest, digest)
            self.assertEqual(pkg.manifest["model_id"], "test-model")
            self.assertEqual(pkg.manifest["security_version"], 2)
            self.assertEqual(pkg.manifest["model_sha256"], mp.file_digest(self.weights)[0])
            self.assertEqual(pkg.manifest["image_sha256"], mp.file_digest(self.package / "model.erofs")[0])
            self.assertEqual(pkg.manifest["tree_sha256"], mp.file_digest(self.package / "model.verity")[0])
            image = self.library / digest / "model.erofs"
            image.rename(image.with_name("old-image"))
            image.write_bytes(b"attacker replacement")
            self.assertEqual(mp.fd_digest(pkg.image_fd)[0], pkg.manifest["image_sha256"])

    def test_changed_signature_tree_and_active_are_rejected(self):
        digest = self.create()
        signature = self.package / "manifest.sig"
        signature.write_bytes(b"\x00" * 64)
        with self.assertRaises(mp.PackageError):
            self.stage()
        self.create_unchanged_signature()
        digest = self.stage()
        self.select(digest)
        altered = bytearray((self.library / digest / "model.verity").read_bytes())
        altered[0] ^= 1
        (self.library / digest / "model.verity").write_bytes(altered)
        with self.assertRaises(mp.PackageError):
            with mp.open_package(self.library, self.public):
                pass
        (self.library / "active").write_text("A" * 64 + "\n")
        with self.assertRaises(mp.PackageError):
            with mp.open_package(self.library, self.public):
                pass

    def create_unchanged_signature(self):
        (self.package / "manifest.json").unlink()
        (self.package / "manifest.sig").unlink()
        self.create()

    def test_stage_detects_image_corruption_before_activation(self):
        self.create()
        altered = bytearray((self.package / "model.erofs").read_bytes())
        altered[0] ^= 1
        (self.package / "model.erofs").write_bytes(altered)
        with self.assertRaises(mp.PackageError):
            self.stage()
        self.assertFalse((self.library / "active").exists())

    def test_copy_refuses_source_growth_and_signer_permissions(self):
        self.private.chmod(0o644)
        with self.assertRaises(mp.PackageError):
            self.create()
        self.private.chmod(0o600)
        source = self.package / "model.erofs"
        with source.open("rb") as stream:
            with self.assertRaises(mp.PackageError):
                mp._copy_fd(stream.fileno(), self.root / "bounded-copy", 2)

    @unittest.skipUnless(hasattr(os, "memfd_create") and hasattr(fcntl, "F_ADD_SEALS"), "Linux memfd seals required")
    def test_runtime_tree_snapshot_is_immutable(self):
        digest = self.create()
        self.stage()
        self.select(digest)
        with mp.open_package(self.library, self.public, snapshot_tree=True) as pkg:
            expected = pkg.manifest["tree_sha256"]
            self.assertEqual(mp.fd_digest(pkg.tree_fd)[0], expected)
            seals = fcntl.fcntl(pkg.tree_fd, fcntl.F_GET_SEALS)
            want = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            self.assertEqual(seals & want, want)
            with self.assertRaises(OSError):
                os.write(pkg.tree_fd, b"x")
            (self.library / digest / "model.verity").write_bytes(b"changed owner bytes")
            self.assertEqual(mp.fd_digest(pkg.tree_fd)[0], expected)

    def test_nofollow_active_directory_and_ancestors(self):
        digest = self.create()
        self.stage()
        self.select(digest)
        (self.library / "active").unlink()
        (self.library / "active").symlink_to(self.package / "manifest.json")
        with self.assertRaises(OSError):
            with mp.open_package(self.library, self.public):
                pass
        (self.library / "active").unlink()
        self.select(digest)
        alternate = self.root / "alternate"
        alternate.symlink_to(self.library, target_is_directory=True)
        with self.assertRaises(OSError):
            with mp.open_package(alternate, self.public):
                pass
        (self.library / digest).rename(self.library / "old-digest")
        (self.library / digest).symlink_to(self.library / "old-digest", target_is_directory=True)
        with self.assertRaises(OSError):
            with mp.open_package(self.library, self.public):
                pass

    def test_manifest_is_exact_canonical_schema(self):
        self.create()
        raw = (self.package / "manifest.json").read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, mp.canonical(value))
        for mutated in (
            raw.replace(b'"v":1', b'"v":true'),
            raw.replace(b'"model_id":"test-model"', b'"model_id":"../bad"'),
            raw.replace(b'"v":1', b'"v":1,"v":1'),
            raw.replace(b'"model_id":', b'"surprise":1,"model_id":'),
            raw[:-1],
        ):
            with self.assertRaises(mp.PackageError):
                mp.validate_manifest(mutated)

    def test_https_download_checks_signed_payloads(self):
        digest = self.create()
        files = {name: (self.package / name).read_bytes() for name in mp.FILES}

        class Opener:
            def open(self, request, timeout):
                return io.BytesIO(files[request.full_url.rsplit("/", 1)[-1]])

        with patch.object(mp, "build_opener", return_value=Opener()):
            actual = mp.download(SimpleNamespace(url="https://models.example.invalid/releases/",
                                                 library=str(self.library), public_key=str(self.public)))
        self.assertEqual(actual, digest)
        self.select(digest)
        with mp.open_package(self.library, self.public) as pkg:
            self.assertEqual(pkg.digest, digest)
        # An already verified package is reused without fetching large files.
        files["model.erofs"] = b"no second large download"
        with patch.object(mp, "build_opener", return_value=Opener()):
            self.assertEqual(mp.download(SimpleNamespace(url="https://models.example.invalid/releases/",
                                                          library=str(self.library), public_key=str(self.public))), digest)
        files["model.erofs"] = b"tampered" + files["model.erofs"]
        with patch.object(mp, "build_opener", return_value=Opener()):
            with self.assertRaises(mp.PackageError):
                mp.download(SimpleNamespace(url="https://models.example.invalid/other/",
                                            library=str(self.root / "other-library"), public_key=str(self.public)))
        # A different signed package with bad payload cannot replace active.
        signed = json.loads(files["manifest.json"])
        signed["model_id"] = "next-model"
        raw = mp.canonical(signed)
        private = serialization.load_pem_private_key(self.private.read_bytes(), password=None)
        files["manifest.json"] = raw
        files["manifest.sig"] = private.sign(raw)
        before = (self.library / "active").read_bytes()
        with patch.object(mp, "build_opener", return_value=Opener()):
            with self.assertRaises(mp.PackageError):
                mp.download(SimpleNamespace(url="https://models.example.invalid/other/",
                                            library=str(self.library), public_key=str(self.public)))
        self.assertEqual((self.library / "active").read_bytes(), before)
        for bad in ("http://models.example.invalid/", "https://user:secret@models.example.invalid/",
                    "https://models.example.invalid/file?query=1"):
            with self.assertRaises(mp.PackageError):
                mp.download(SimpleNamespace(url=bad, library=str(self.library), public_key=str(self.public)))
        with self.assertRaises(mp.PackageError):
            mp._HttpsRedirect().redirect_request(Request("https://models.example.invalid/model/"),
                                                 None, 302, "Found", {}, "http://models.example.invalid/model/")


if __name__ == "__main__":
    unittest.main()
