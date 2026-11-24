#!/usr/bin/env python3
"""Create a canonical manifest for a complete signed text release; never signs."""
import argparse
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bundle import canonical, DOMAIN, NAMES, parse_manifest

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("staging", type=Path)
p.add_argument("--sequence", type=int, required=True)
a = p.parse_args()
install_id = (a.staging / "out/install-id").read_text().removesuffix("\n")
rows = []
for name in sorted(NAMES):
    path = a.staging / name
    if path.is_symlink() or not path.is_file():
        p.error("payload must contain only regular files")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4*1024*1024), b""):
            digest.update(chunk)
    rows.append({"name": name, "size": path.stat().st_size, "sha256": digest.hexdigest()})
raw = canonical({"v": 1, "domain": DOMAIN, "sequence": a.sequence, "install_id": install_id, "files": rows})
parse_manifest(raw)
(a.staging / "manifest.json").write_bytes(raw)
print("Manifest written; sign its exact bytes with the enrolled workstation boot key.")
