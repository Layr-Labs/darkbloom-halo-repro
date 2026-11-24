#!/usr/bin/env python3
"""Create and select independently signed, dm-verity protected text models.

The active selection and package files may live on the owner's writable disk.
Only the pinned Ed25519 public key authorizes metadata; the signed verity root
authenticates image blocks when the measured initrd opens dm-verity. Callers
must keep the returned file descriptors open until veritysetup has opened them.
"""

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler, Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


DOMAIN = "darkbloom/model-package/v1"
MANIFEST_FIELDS = frozenset({
    "v", "domain", "model_id", "model_sha256", "model_size", "verity_root",
    "image_size", "tree_size", "image_sha256", "tree_sha256", "workflow_sha256",
    "engine_version", "security_version",
})
HEX = re.compile(r"[0-9a-f]{64}\Z")
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
ENGINE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:_-]{0,79}\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_MANIFEST = 4096
MAX_KEY = 8192
MAX_OBJECT = (1 << 63) - 1
MAX_DOWNLOAD = 1 << 40  # Cap a single package file at one TiB.
FILES = ("manifest.json", "manifest.sig", "model.erofs", "model.verity")


class PackageError(ValueError):
    """A public, content-free package rejection."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError("duplicate model metadata field")
        result[key] = value
    return result


def validate_manifest(raw):
    if not 0 < len(raw) <= MAX_MANIFEST:
        raise PackageError("invalid model manifest")
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise PackageError("invalid model manifest") from exc
    if not isinstance(value, dict) or set(value) != MANIFEST_FIELDS or raw != canonical(value):
        raise PackageError("invalid model manifest")
    if type(value["v"]) is not int or value["v"] != 1 or value["domain"] != DOMAIN:
        raise PackageError("invalid model manifest")
    if (not isinstance(value["model_id"], str) or not MODEL_ID.fullmatch(value["model_id"])
            or not isinstance(value["engine_version"], str)
            or not ENGINE_VERSION.fullmatch(value["engine_version"])):
        raise PackageError("invalid model identity")
    for name in ("model_sha256", "verity_root", "image_sha256", "tree_sha256", "workflow_sha256"):
        if not isinstance(value[name], str) or not HEX.fullmatch(value[name]):
            raise PackageError("invalid model digest")
    for name in ("model_size", "image_size", "tree_size", "security_version"):
        maximum = (1 << 32) - 1 if name == "security_version" else MAX_OBJECT
        if type(value[name]) is not int or not 0 < value[name] <= maximum:
            raise PackageError("invalid model size or version")
    return value


def open_directory(path):
    """Walk an absolute path from / without following any component symlink."""
    path = Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise PackageError("model directory must be an absolute path")
    descriptor = os.open("/", DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def make_directory(path):
    """Create missing owner library components without following symlinks."""
    path = Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise PackageError("model directory must be an absolute path")
    descriptor = os.open("/", DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular(directory_fd, name, maximum=None):
    descriptor = os.open(name, FILE_FLAGS, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or (maximum is not None and info.st_size > maximum):
            raise PackageError("invalid model package file")
        return descriptor, info.st_size
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(directory_fd, name, maximum):
    descriptor, size = _open_regular(directory_fd, name, maximum)
    try:
        raw = bytearray()
        while len(raw) < size:
            chunk = os.read(descriptor, min(65536, size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != size or os.fstat(descriptor).st_size != size:
            raise PackageError("model package file changed")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _read_key(path, *, private=False):
    descriptor = os.open(path, FILE_FLAGS)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_KEY
                or (private and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
            raise PackageError("invalid model signing key")
        raw = os.read(descriptor, MAX_KEY + 1)
        if len(raw) != info.st_size:
            raise PackageError("model signing key changed")
        return raw
    finally:
        os.close(descriptor)


def fd_digest(descriptor):
    """Hash the same held inode that dm-verity will subsequently open."""
    initial = os.fstat(descriptor)
    if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= MAX_OBJECT:
        raise PackageError("invalid model package file")
    digest = hashlib.sha256()
    offset = 0
    while offset < initial.st_size:
        chunk = os.pread(descriptor, min(4 * 1024 * 1024, initial.st_size - offset), offset)
        if not chunk:
            raise PackageError("model package file changed")
        digest.update(chunk)
        offset += len(chunk)
    current = os.fstat(descriptor)
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns):
        raise PackageError("model package file changed")
    return digest.hexdigest(), offset


def _public_key(path):
    try:
        key = serialization.load_pem_public_key(_read_key(path))
    except (TypeError, ValueError) as exc:
        raise PackageError("invalid model signing key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PackageError("model signing key must be Ed25519")
    return key


def _private_key(path):
    try:
        key = serialization.load_pem_private_key(_read_key(path, private=True), password=None)
    except (TypeError, ValueError) as exc:
        raise PackageError("invalid model signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PackageError("model signing key must be Ed25519")
    return key


def _check_signature(raw, signature, public_key):
    if len(signature) != 64:
        raise PackageError("invalid model signature")
    try:
        _public_key(public_key).verify(signature, raw)
    except Exception as exc:
        raise PackageError("model signature verification failed") from exc


def _snapshot_tree(source_fd, expected_sha, expected_size, stack):
    """Copy the signed hash tree once into sealed anonymous RAM."""
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise PackageError("immutable model tree snapshot is unavailable")
    try:
        target_fd = os.memfd_create("darkbloom-verity-tree", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except OSError as exc:
        raise PackageError("immutable model tree snapshot failed") from exc
    stack.callback(os.close, target_fd)
    original = os.fstat(source_fd)
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(source_fd, min(4 * 1024 * 1024, expected_size - offset), offset)
        if not chunk:
            raise PackageError("model verity tree changed")
        digest.update(chunk)
        written = 0
        while written < len(chunk):
            result = os.write(target_fd, chunk[written:])
            if result <= 0:
                raise PackageError("immutable model tree snapshot failed")
            written += result
        offset += len(chunk)
    current = os.fstat(source_fd)
    if (digest.hexdigest() != expected_sha or offset != expected_size
            or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            != (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns)):
        raise PackageError("model verity tree differs from signature")
    try:
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(target_fd, fcntl.F_ADD_SEALS, seals)
    except (AttributeError, OSError) as exc:
        raise PackageError("immutable model tree snapshot failed") from exc
    os.lseek(target_fd, 0, os.SEEK_SET)
    return target_fd


def _open_verified(root_fd, digest, public_key, stack, *, snapshot_tree=False):
    if not HEX.fullmatch(digest):
        raise PackageError("invalid selected model")
    package_fd = os.open(digest, DIR_FLAGS, dir_fd=root_fd)
    stack.callback(os.close, package_fd)
    raw = _read_regular(package_fd, "manifest.json", MAX_MANIFEST)
    manifest = validate_manifest(raw)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise PackageError("selected model digest differs")
    signature = _read_regular(package_fd, "manifest.sig", 64)
    _check_signature(raw, signature, public_key)
    image_fd, image_size = _open_regular(package_fd, "model.erofs")
    stack.callback(os.close, image_fd)
    tree_fd, tree_size = _open_regular(package_fd, "model.verity")
    stack.callback(os.close, tree_fd)
    if image_size != manifest["image_size"] or tree_size != manifest["tree_size"]:
        raise PackageError("model package size differs from signature")
    if snapshot_tree:
        tree_fd = _snapshot_tree(tree_fd, manifest["tree_sha256"], tree_size, stack)
    elif fd_digest(tree_fd) != (manifest["tree_sha256"], tree_size):
        raise PackageError("model verity tree differs from signature")
    return SimpleNamespace(manifest=manifest, manifest_raw=raw, digest=digest,
                           directory_fd=package_fd, image_fd=image_fd, tree_fd=tree_fd)


@contextmanager
def open_package(library: Path, public_key: Path, *, snapshot_tree=False):
    """Open the exact selected signed package with stable nofollow descriptors.

    The caller must verify the signed verity root through dm-verity before
    reading model bytes or reporting the package as admitted.
    """
    with ExitStack() as stack:
        root_fd = open_directory(library)
        stack.callback(os.close, root_fd)
        active = _read_regular(root_fd, "active", 65)
        if not re.fullmatch(rb"[0-9a-f]{64}\n", active):
            raise PackageError("invalid active model selection")
        yield _open_verified(root_fd, active[:-1].decode("ascii"), public_key, stack,
                             snapshot_tree=snapshot_tree)


def file_digest(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise PackageError("model input must be a regular file")
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    if not 0 < size <= MAX_OBJECT:
        raise PackageError("invalid model input size")
    return digest.hexdigest(), size


def _write_new(directory_fd, name, raw, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=directory_fd)
    try:
        with os.fdopen(os.dup(fd), "wb") as out:
            out.write(raw)
            out.flush()
        os.fsync(fd)
    finally:
        os.close(fd)


def create(args):
    package = Path(args.package)
    package_fd = open_directory(package)
    try:
        image_fd, image_size = _open_regular(package_fd, "model.erofs")
        try:
            tree_fd, tree_size = _open_regular(package_fd, "model.verity")
            try:
                image_sha, confirmed_image_size = fd_digest(image_fd)
                tree_sha, confirmed_tree_size = fd_digest(tree_fd)
            finally:
                os.close(tree_fd)
        finally:
            os.close(image_fd)
        if confirmed_image_size != image_size or confirmed_tree_size != tree_size:
            raise PackageError("model package file changed")
        weights_sha, weights_size = file_digest(args.weights)
        workflow_sha, _ = file_digest(args.workflow)
        root = args.verity_root
        value = dict(v=1, domain=DOMAIN, model_id=args.model_id,
                     model_sha256=weights_sha, model_size=weights_size,
                     verity_root=root, image_size=image_size, tree_size=tree_size,
                     image_sha256=image_sha, tree_sha256=tree_sha,
                     workflow_sha256=workflow_sha, engine_version=args.engine_version,
                     security_version=args.security_version)
        raw = canonical(value)
        validate_manifest(raw)
        signature = _private_key(args.private_key).sign(raw)
        if len(signature) != 64:
            raise PackageError("model signature creation failed")
        _write_new(package_fd, "manifest.json", raw, 0o644)
        try:
            _write_new(package_fd, "manifest.sig", signature, 0o644)
        except BaseException:
            os.unlink("manifest.json", dir_fd=package_fd)
            raise
        os.fsync(package_fd)
        return hashlib.sha256(raw).hexdigest()
    finally:
        os.close(package_fd)


def _copy_fd(source_fd, destination, expected_size):
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(os.dup(source_fd), "rb") as source, open(destination, "xb") as target:
        source.seek(0)
        while size < expected_size:
            chunk = source.read(min(4 * 1024 * 1024, expected_size - size))
            if not chunk:
                break
            target.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        if source.read(1):
            raise PackageError("model source exceeds signed size")
        target.flush()
        os.fsync(target.fileno())
    destination.chmod(0o600)
    return digest.hexdigest(), size


def _existing_verified(root_fd, digest, public_key):
    """A prior selection is reusable only if its full signed bytes still match."""
    if not HEX.fullmatch(digest):
        raise PackageError("invalid selected model")
    try:
        probe = os.open(digest, DIR_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return False
    os.close(probe)
    with ExitStack() as stack:
        pkg = _open_verified(root_fd, digest, public_key, stack)
        if fd_digest(pkg.image_fd) != (pkg.manifest["image_sha256"], pkg.manifest["image_size"]):
            raise PackageError("existing model image differs from signature")
        return True


def stage(args):
    source = Path(args.package)
    source_fd = open_directory(source)
    library = Path(args.library)
    try:
        library_fd = make_directory(library)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        raw = _read_regular(source_fd, "manifest.json", MAX_MANIFEST)
        digest = hashlib.sha256(raw).hexdigest()
        if _existing_verified(library_fd, digest, args.public_key):
            return digest
        signature = _read_regular(source_fd, "manifest.sig", 64)
        with ExitStack() as stack:
            # Source directories are independently verified without assuming
            # they are already named by their manifest digest.
            manifest = validate_manifest(raw)
            _check_signature(raw, signature, args.public_key)
            image_fd, image_size = _open_regular(source_fd, "model.erofs")
            stack.callback(os.close, image_fd)
            tree_fd, tree_size = _open_regular(source_fd, "model.verity")
            stack.callback(os.close, tree_fd)
            if image_size != manifest["image_size"] or tree_size != manifest["tree_size"]:
                raise PackageError("model package size differs from signature")
            temporary = Path(tempfile.mkdtemp(prefix=".model-stage-", dir=library))
            try:
                for name, content in (("manifest.json", raw),
                                      ("manifest.sig", signature)):
                    with open(temporary / name, "xb") as out:
                        out.write(content)
                        out.flush()
                        os.fsync(out.fileno())
                    (temporary / name).chmod(0o600)
                if _copy_fd(image_fd, temporary / "model.erofs", image_size) != (manifest["image_sha256"], image_size):
                    raise PackageError("model image differs from signature")
                if _copy_fd(tree_fd, temporary / "model.verity", tree_size) != (manifest["tree_sha256"], tree_size):
                    raise PackageError("model tree differs from signature")
                try:
                    os.rename(temporary, library / digest)
                except FileExistsError:
                    if not _existing_verified(library_fd, digest, args.public_key):
                        raise
                os.fsync(library_fd)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        return digest
    finally:
        os.close(source_fd)
        os.close(library_fd)


def select(args):
    library = Path(args.library)
    with ExitStack() as stack:
        root_fd = open_directory(library)
        stack.callback(os.close, root_fd)
        if not _existing_verified(root_fd, args.digest, args.public_key):
            raise PackageError("selected model package is missing")
        temporary = f".active-{secrets.token_hex(12)}"
        _write_new(root_fd, temporary, (args.digest + "\n").encode("ascii"), 0o600)
        try:
            os.rename(temporary, "active", src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass


class _HttpsRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        original = urlsplit(request.full_url)
        target = urlsplit(new_url)
        if target.scheme != "https" or target.netloc != original.netloc:
            raise PackageError("model download redirected outside HTTPS origin")
        return super().redirect_request(request, fp, code, msg, headers, new_url)


def _download_url(base, name):
    return base + name


def _download_small(opener, base, name, maximum):
    with opener.open(Request(_download_url(base, name), headers={"Accept": "application/octet-stream"}), timeout=120) as response:
        raw = response.read(maximum + 1)
    if not 0 < len(raw) <= maximum:
        raise PackageError("invalid downloaded model metadata")
    return raw


def _download_file(opener, base, name, target, expected_size, expected_sha):
    if expected_size > MAX_DOWNLOAD:
        raise PackageError("downloaded model file exceeds size limit")
    digest = hashlib.sha256()
    count = 0
    with opener.open(Request(_download_url(base, name), headers={"Accept": "application/octet-stream"}), timeout=120) as response:
        with open(target, "xb") as output:
            while count < expected_size:
                chunk = response.read(min(4 * 1024 * 1024, expected_size - count))
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                count += len(chunk)
            if response.read(1):
                raise PackageError("downloaded model file exceeds signed size")
            output.flush()
            os.fsync(output.fileno())
    if count != expected_size or digest.hexdigest() != expected_sha:
        raise PackageError("downloaded model file differs from signature")
    target.chmod(0o600)


def download(args):
    location = urlsplit(args.url)
    if (location.scheme != "https" or not location.hostname or location.username or location.password
            or location.query or location.fragment or not location.path.endswith("/")):
        raise PackageError("model download requires an HTTPS directory URL")
    base = args.url
    opener = build_opener(HTTPSHandler(), _HttpsRedirect())
    raw = _download_small(opener, base, "manifest.json", MAX_MANIFEST)
    manifest = validate_manifest(raw)
    signature = _download_small(opener, base, "manifest.sig", 64)
    _check_signature(raw, signature, args.public_key)
    digest = hashlib.sha256(raw).hexdigest()
    library = Path(args.library)
    library_fd = make_directory(library)
    temporary = None
    try:
        if _existing_verified(library_fd, digest, args.public_key):
            return digest
        temporary = Path(tempfile.mkdtemp(prefix=".model-download-", dir=library))
        for name, content in (("manifest.json", raw), ("manifest.sig", signature)):
            with open(temporary / name, "xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            (temporary / name).chmod(0o600)
        _download_file(opener, base, "model.erofs", temporary / "model.erofs",
                       manifest["image_size"], manifest["image_sha256"])
        _download_file(opener, base, "model.verity", temporary / "model.verity",
                       manifest["tree_size"], manifest["tree_sha256"])
        try:
            os.rename(temporary, library / digest)
        except FileExistsError:
            if not _existing_verified(library_fd, digest, args.public_key):
                raise
        os.fsync(library_fd)
        return digest
    finally:
        os.close(library_fd)
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create", help="sign metadata for model.erofs/model.verity in a package directory")
    for flag in ("package", "weights", "workflow", "model-id", "engine-version", "verity-root", "security-version", "private-key"):
        create_parser.add_argument("--" + flag, required=True, type=int if flag == "security-version" else str)
    stage_parser = sub.add_parser("stage", help="verify and copy a package into the owner library")
    for flag in ("package", "library", "public-key"):
        stage_parser.add_argument("--" + flag, required=True)
    select_parser = sub.add_parser("select", help="atomically activate an already staged package")
    for flag in ("digest", "library", "public-key"):
        select_parser.add_argument("--" + flag, required=True)
    download_parser = sub.add_parser("download", help="download the four fixed package files over HTTPS")
    for flag in ("url", "library", "public-key"):
        download_parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "create":
        print(create(args))
    elif args.command == "stage":
        print(stage(args))
    elif args.command == "download":
        print(download(args))
    else:
        select(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, PackageError):
        print("Model package verification or selection failed.", file=sys.stderr)
        sys.exit(1)
