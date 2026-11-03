#!/usr/bin/env python3
"""Check exact DER presence in shim's runtime MOK variables, read-only.

Exit status: 0 = enrolled, 1 = absent, 2 = read/format error.
This checks MOK certificate enrollment, not Secure Boot enforcement or bootability.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
import uuid
from pathlib import Path


SHIM_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le
LIST_HEADER = struct.Struct("<16sIII")
VARIABLE_NAME = re.compile(r"MokListRT(?:[0-9]+)?-" + SHIM_GUID, re.IGNORECASE)


def parse_signature_lists(data):
    """Yield (signature type, certificate/hash bytes) from validated EFI lists."""
    offset = 0
    while offset < len(data):
        if len(data) - offset < LIST_HEADER.size:
            raise ValueError(f"truncated EFI_SIGNATURE_LIST at byte {offset}")
        kind, size, header_size, entry_size = LIST_HEADER.unpack_from(data, offset)
        if size < LIST_HEADER.size or size > len(data) - offset:
            raise ValueError(f"invalid SignatureListSize at byte {offset}")
        if header_size > size - LIST_HEADER.size:
            raise ValueError(f"invalid SignatureHeaderSize at byte {offset}")
        if entry_size < 16:
            raise ValueError(f"invalid SignatureSize at byte {offset}")
        entries_start = offset + LIST_HEADER.size + header_size
        entries_size = size - LIST_HEADER.size - header_size
        if entries_size % entry_size:
            raise ValueError(f"misaligned signature entries at byte {offset}")
        for start in range(entries_start, offset + size, entry_size):
            # Each EFI_SIGNATURE_DATA begins with its 16-byte SignatureOwner.
            yield kind, data[start + 16:start + entry_size]
        offset += size


def check(cert, directory):
    result = {
        "certificate_sha256": hashlib.sha256(cert).hexdigest().upper(),
        "enrolled": False,
        "scope": "exact DER certificate in shim MokListRT variables",
        "variables": [],
    }
    if not cert:
        raise ValueError("certificate file is empty")
    if not directory.is_dir():
        raise ValueError(f"EFI variable directory unavailable: {directory}")
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if not VARIABLE_NAME.fullmatch(path.name):
            continue
        # efivarfs can reject seeking: use a single sequential read.
        with path.open("rb") as stream:
            variable = stream.read()
        if len(variable) < 4:
            raise ValueError(f"{path.name}: missing EFI variable attributes")
        counts = {"name": path.name, "x509_entries": 0, "matching_entries": 0}
        try:
            for kind, entry in parse_signature_lists(variable[4:]):
                if kind != X509_GUID:
                    continue
                counts["x509_entries"] += 1
                if entry == cert:
                    counts["matching_entries"] += 1
                    result["enrolled"] = True
        except ValueError as error:
            raise ValueError(f"{path.name}: {error}") from error
        result["variables"].append(counts)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path, help="DER certificate to find")
    parser.add_argument("--efivar-dir", type=Path,
                        default=Path("/sys/firmware/efi/efivars"))
    args = parser.parse_args()
    result = {"enrolled": None}
    try:
        cert = args.certificate.read_bytes()
        result["certificate_sha256"] = hashlib.sha256(cert).hexdigest().upper()
        result = check(cert, args.efivar_dir)
    except (OSError, ValueError) as error:
        result["error"] = str(error)
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["enrolled"] else 1


if __name__ == "__main__":
    sys.exit(main())
