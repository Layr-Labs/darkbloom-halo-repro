"""Catalog handoff fixtures; all device and mount commands are mocked."""
import configparser
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "nodeos/text/rootfs/usr/lib/darkbloom/catalog-model.py"
SPEC = importlib.util.spec_from_file_location("catalog_runtime", SCRIPT)
CATALOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CATALOG)
EXPECTED = dict(v=1, library="/run/nodeos/host/home/operator/.local/share/darkbloom/models",
                engine_version="1:0.2.0+test", workflow_sha256="a" * 64)


class CatalogRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catalog-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.runtime = self.base / "runtime"
        self.runtime.mkdir()
        self.mapper = self.base / "mapper-device"
        self.models = self.base / "models"
        (self.models / "text").mkdir(parents=True)
        self.models.chmod(0o755)
        (self.models / "text").chmod(0o755)
        self.weights = self.models / "text/model.gguf"
        self.weights.write_bytes(b"synthetic GGUF fixture")
        self.weights.chmod(0o644)
        self.manifest = dict(v=1,domain="darkbloom/model-package/v1",model_id="fixture-model",
                             model_sha256="b" * 64,model_size=self.weights.stat().st_size,
                             verity_root="c" * 64,image_sha256="d" * 64,image_size=4096,
                             tree_sha256="e" * 64,tree_size=4096,workflow_sha256=EXPECTED["workflow_sha256"],
                             engine_version=EXPECTED["engine_version"],security_version=1)
        self.raw = (json.dumps(self.manifest,sort_keys=True,separators=(",", ":")) + "\n").encode()
        for name, value in (("RUNTIME", self.runtime), ("MAPPER", str(self.mapper)), ("MODELS", self.models)):
            patch = mock.patch.object(CATALOG, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def api(self, manifest=None):
        manifest = manifest or self.manifest
        raw = (json.dumps(manifest,sort_keys=True,separators=(",", ":")) + "\n").encode()
        image = self.base / "image.erofs"
        tree = self.base / "tree.verity"
        image.write_bytes(b"fixture image")
        tree.write_bytes(b"fixture tree")
        @contextmanager
        def package(library, public_key, *, snapshot_tree):
            self.assertEqual(library, Path(EXPECTED["library"]))
            self.assertEqual(public_key, CATALOG.PUBLIC_KEY)
            self.assertTrue(snapshot_tree)
            with image.open("rb") as data, tree.open("rb") as hashes:
                yield SimpleNamespace(manifest=manifest,manifest_raw=raw,image_fd=data.fileno(),tree_fd=hashes.fileno())
        return {"open_package": package, "validate_manifest": json.loads}

    def owner_root(self):
        original = os.fstat
        def mapped(descriptor):
            info = original(descriptor)
            return SimpleNamespace(st_uid=0,st_mode=info.st_mode,st_size=info.st_size)
        return mock.patch.object(CATALOG.os, "fstat", side_effect=mapped)

    def test_catalog_policy_requires_exact_signed_mode_and_exact_root_library(self):
        raw = json.dumps(EXPECTED).encode()
        self.assertEqual(CATALOG.policy(raw, "nodeos.model-mode=catalog"), EXPECTED)
        for cmdline, value in (("quiet", EXPECTED), ("nodeos.model-mode=pinned", EXPECTED),
                               ("nodeos.model-mode=catalog nodeos.model-mode=catalog", EXPECTED),
                               ("nodeos.model-mode=catalog", EXPECTED | {"library":"/home/operator/models"}),
                               ("nodeos.model-mode=catalog", EXPECTED | {"library":EXPECTED["library"] + "/../other"})):
            with self.subTest(cmdline=cmdline), self.assertRaises(ValueError):
                CATALOG.policy(json.dumps(value).encode(), cmdline)

    def test_open_binds_held_fds_and_writes_only_pending_metadata(self):
        calls = []
        def command(args, *, pass_fds=()):
            calls.append((args,pass_fds))
            self.assertEqual(len(pass_fds), 2)
            self.assertEqual(args[2], f"/proc/self/fd/{pass_fds[0]}")
            self.assertEqual(args[4], f"/proc/self/fd/{pass_fds[1]}")
            for descriptor in pass_fds:
                self.assertGreater(os.fstat(descriptor).st_size, 0)
            self.mapper.write_bytes(b"mock mapper")
        with mock.patch.object(CATALOG, "command", side_effect=command), \
             mock.patch.object(CATALOG, "mapper_identity", return_value=(None,"/dev/dm-99")):
            CATALOG.open_mapping(EXPECTED, self.api())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][3], "nodeos-catalog-model")
        self.assertEqual(os.readlink(self.runtime / "mapper"), "/dev/dm-99")
        self.assertEqual((self.runtime / "manifest.pending").read_bytes(), self.raw)
        self.assertFalse((self.runtime / "model.env").exists())
        self.assertFalse((self.runtime / "manifest.json").exists())

    def test_engine_or_workflow_mismatch_never_opens_a_mapping(self):
        for key in ("engine_version", "workflow_sha256"):
            with self.subTest(key=key), mock.patch.object(CATALOG, "command") as command:
                changed = self.manifest | {key: "different"}
                with self.assertRaises(ValueError):
                    CATALOG.open_mapping(EXPECTED, self.api(changed))
                command.assert_not_called()
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_existing_mapping_or_runtime_state_is_never_replaced(self):
        self.mapper.write_bytes(b"preexisting")
        with mock.patch.object(CATALOG, "command") as command, self.assertRaises(ValueError):
            CATALOG.open_mapping(EXPECTED, self.api())
        command.assert_not_called()
        self.assertEqual(self.mapper.read_bytes(), b"preexisting")

    def test_ready_publishes_only_verified_values_and_preserves_existing_settings(self):
        (self.runtime / "manifest.pending").write_bytes(self.raw)
        with self.owner_root(), mock.patch.object(CATALOG, "check_mount"):
            CATALOG.ready(EXPECTED, self.api())
            with self.assertRaises(ValueError):
                CATALOG.ready(EXPECTED, self.api())
        self.assertEqual((self.runtime / "manifest.json").read_bytes(), self.raw)
        self.assertEqual((self.runtime / "model.env").read_text(),
                         "DB_TEXT_MODEL_ID=fixture-model\nDB_TEXT_MODEL_SHA256=" + "b" * 64 + "\n")
        for name in ("manifest.json", "model.env"):
            self.assertEqual(stat.S_IMODE((self.runtime / name).stat().st_mode), 0o640)

    def test_symlink_wrong_size_or_unreadable_weights_never_publish_settings(self):
        (self.runtime / "manifest.pending").write_bytes(self.raw)
        for failure in ("symlink", "size", "permissions"):
            with self.subTest(failure=failure):
                self.weights.unlink()
                if failure == "symlink":
                    self.weights.symlink_to(self.base / "elsewhere")
                else:
                    self.weights.write_bytes(b"wrong" if failure == "size" else b"synthetic GGUF fixture")
                    self.weights.chmod(0o600 if failure == "permissions" else 0o644)
                with self.owner_root(), mock.patch.object(CATALOG, "check_mount"), self.assertRaises((OSError,ValueError)):
                    CATALOG.ready(EXPECTED, self.api())
                self.assertFalse((self.runtime / "model.env").exists())
                self.assertFalse((self.runtime / "manifest.json").exists())

    def test_ready_rejects_mount_failure_before_exposing_settings(self):
        (self.runtime / "manifest.pending").write_bytes(self.raw)
        with self.owner_root(), mock.patch.object(CATALOG, "check_mount", side_effect=ValueError("fixture")), self.assertRaises(ValueError):
            CATALOG.ready(EXPECTED, self.api())
        self.assertFalse((self.runtime / "model.env").exists())


class CatalogUnitTests(unittest.TestCase):
    def parse(self, name):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = str
        parser.read(ROOT / "nodeos/text/rootfs" / name)
        return parser

    def test_mount_handoff_and_privileges_are_fixed_and_late(self):
        mount = self.parse("usr/lib/darkbloom/catalog-model.mount")
        self.assertEqual(mount["Unit"]["DefaultDependencies"], "no")
        self.assertEqual(mount["Unit"]["Requires"], "darkbloom-model-open.service")
        self.assertEqual(mount["Mount"]["What"], "/run/darkbloom-model/mapper")
        self.assertEqual(mount["Mount"]["Type"], "erofs")
        self.assertEqual(set(mount["Mount"]["Options"].split(",")), {"ro","nodev","nosuid","noexec"})
        opener = self.parse("etc/systemd/system/darkbloom-model-open.service")["Service"]
        self.assertEqual(set(opener["CapabilityBoundingSet"].split()), {"CAP_SYS_ADMIN","CAP_DAC_READ_SEARCH","CAP_MKNOD"})
        self.assertEqual(opener["PrivateNetwork"], "yes")
        self.assertEqual(opener["DevicePolicy"], "closed")
        ready = self.parse("etc/systemd/system/darkbloom-model-ready.service")
        self.assertEqual(ready["Unit"]["Requires"], "usr-share-darkbloom-models.mount")
        self.assertEqual(ready["Service"]["CapabilityBoundingSet"], "")
        self.assertEqual(ready["Service"]["Group"], "dbnode")


if __name__ == "__main__":
    unittest.main()
