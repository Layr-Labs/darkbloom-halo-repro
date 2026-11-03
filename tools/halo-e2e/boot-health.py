#!/usr/bin/python3
"""Fixed, pre-admission boot warning census with bounded diagnostic detail.

No arguments prints counts only. The root-owned Node OS unit requests bounded
detail once before any Darkbloom request is admitted.
"""

import json
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path


BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MAX_RECORDS = 10_000
MAX_LINE_BYTES = 32_768
MAX_FAILED_UNITS = 16
MAX_UNKNOWN_SUMMARIES = 32
MAX_REPORT_BYTES = 16 * 1024
UNIT_NAME = re.compile(r"[A-Za-z0-9@_.-]{1,96}\Z")
UUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")
# AMD TEE's firmware filename has 8-4-4-16 hex groups (see copy_ta_binary).
TA_FIRMWARE = re.compile(r"amdtee/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{16}\.bin\b")
NPU_REVISION = re.compile(r"unknown device revision:\s*([0-9]{1,3})(?:\s*\(raw fuse:\s*0x([0-9a-f]{1,8})\))?")
KNOWN_COUNTERS = (
    "amdxdna_unknown_revision",
    "amdtee_firmware_missing",
    "amd_pmf_ta_failure",
    "ima_sha384_unavailable",
    "bpf_restrict_fs_failure",
)
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}


def empty_report(boot_id):
    report = {
        "v": 1,
        "boot_id": boot_id,
        "warning_count": 0,
        "unknown_warning_count": 0,
        "collection_error_count": 0,
        "failed_unit_count": 0,
        "failed_units": [],
        "unknown_summaries": [],
        "amdxdna_reported_revision": None,
        "amdxdna_raw_fuse": None,
        "amdtee_missing_firmware": [],
    }
    report.update({key: 0 for key in KNOWN_COUNTERS})
    return report


def warning_id(message):
    """Map known boot failures to fixed IDs; never return the message."""
    m = message.lower()
    if "amdxdna" in m and "aie2_get_dev_revision" in m and "unknown device revision" in m:
        return "amdxdna_unknown_revision"
    if "amdtee" in m and "firmware" in m and ("fail" in m or "missing" in m):
        return "amdtee_firmware_missing"
    if ("amd-pmf" in m or "amd_pmf" in m) and re.search(r"\bta\b|trusted application", m) and ("fail" in m or "error" in m):
        return "amd_pmf_ta_failure"
    if "ima:" in m and "sha384" in m and "can not allocate" in m:
        return "ima_sha384_unavailable"
    if "bpf-restrict-fs" in m and "failed to load" in m:
        return "bpf_restrict_fs_failure"
    return "unknown_warning_count"


def unknown_summary(record, message):
    try:
        priority = int(record.get("PRIORITY", 4))
    except (TypeError, ValueError):
        priority = 4
    if priority not in range(5):
        priority = 4
    transport = "kernel" if record.get("_TRANSPORT") == "kernel" else "systemd"
    unit = record.get("_SYSTEMD_UNIT") or record.get("UNIT") or ""
    if not isinstance(unit, str) or (unit and not UNIT_NAME.fullmatch(unit)):
        unit = ""
    # The excerpt is a boot-time operational aid. Reduce it to one ASCII line,
    # strip control sequences and long opaque tokens, and redact sensitive
    # labels. The fixed unit runs before dbnode can accept any request.
    excerpt = "".join(ch if 32 <= ord(ch) <= 126 and ch not in '\\"' else " " for ch in message)
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    excerpt = re.sub(r"[A-Za-z0-9+/=]{40,}", "[long-token]", excerpt)
    if re.search(r"\b(?:password|passphrase|secret|token|prompt|psk|ssid|api.key)\b", excerpt, re.I):
        excerpt = "[redacted-sensitive-warning]"
    return {
        "priority": priority,
        "transport": transport,
        "unit": unit,
        "sha256": hashlib.sha256(message.encode("utf-8", "replace")).hexdigest(),
        "excerpt": excerpt[:256],
    }


def add_warning(report, message, record=None, details=False):
    key = warning_id(message)
    report[key] += 1
    report["warning_count"] += 1
    if key == "unknown_warning_count" and details and isinstance(record, dict) and len(report["unknown_summaries"]) < MAX_UNKNOWN_SUMMARIES:
        report["unknown_summaries"].append(unknown_summary(record, message))
    if key == "amdxdna_unknown_revision":
        found = NPU_REVISION.search(message.lower())
        if found:
            revision = int(found.group(1), 10)
            fuse = int(found.group(2), 16) if found.group(2) is not None else None
            if report["amdxdna_reported_revision"] not in (None, revision):
                report["collection_error_count"] += 1
            report["amdxdna_reported_revision"] = revision
            if fuse is not None:
                if report["amdxdna_raw_fuse"] not in (None, fuse):
                    report["collection_error_count"] += 1
                report["amdxdna_raw_fuse"] = fuse
    elif key == "amdtee_firmware_missing":
        found = TA_FIRMWARE.search(message)
        if found and found.group(0) not in report["amdtee_missing_firmware"]:
            if len(report["amdtee_missing_firmware"]) < 4:
                report["amdtee_missing_firmware"].append(found.group(0))
            else:
                report["collection_error_count"] += 1


def add_failed_unit(report, name):
    report["failed_unit_count"] += 1
    if UNIT_NAME.fullmatch(name) and len(report["failed_units"]) < MAX_FAILED_UNITS:
        report["failed_units"].append(name)
    elif not UNIT_NAME.fullmatch(name):
        report["collection_error_count"] += 1


def is_boot_system_record(record):
    """Limit census to kernel and systemd records, never user application logs."""
    if record.get("_TRANSPORT") == "kernel" or str(record.get("_PID")) == "1":
        return True
    # SYSLOG_IDENTIFIER is sender supplied. The underscored executable and
    # UID fields come from journald and prevent a user app spoofing systemd.
    exe = record.get("_EXE", "")
    return str(record.get("_UID")) == "0" and isinstance(exe, str) and exe.startswith(("/usr/lib/systemd/", "/lib/systemd/"))


def capture_journal(report, details=False):
    cmd = ["/usr/bin/journalctl", "--system", "--boot=0", "--priority=warning", "--output=json", "--no-pager", "--all"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
    except OSError:
        report["collection_error_count"] += 1
        return
    try:
        if proc.stdout is None:
            raise OSError("journal stdout unavailable")
        for n in range(MAX_RECORDS + 1):
            line = proc.stdout.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES or n == MAX_RECORDS:
                report["collection_error_count"] += 1
                proc.kill()
                break
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or not is_boot_system_record(record):
                    continue
                message = record.get("MESSAGE", "")
                if not isinstance(message, str):
                    message = ""
                    report["collection_error_count"] += 1
                add_warning(report, message, record, details)
            except (ValueError, TypeError, AttributeError):
                add_warning(report, "")
                report["collection_error_count"] += 1
        proc.stdout.close()
        if proc.wait(timeout=5) != 0:
            report["collection_error_count"] += 1
    except (OSError, subprocess.TimeoutExpired):
        proc.kill()
        proc.wait()
        report["collection_error_count"] += 1


def capture_failed_units(report):
    cmd = ["/usr/bin/systemctl", "--failed", "--all", "--no-legend", "--plain", "--no-pager"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
    except OSError:
        report["collection_error_count"] += 1
        return
    try:
        if proc.stdout is None:
            raise OSError("failed-unit stdout unavailable")
        for n in range(MAX_RECORDS + 1):
            line = proc.stdout.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES or n == MAX_RECORDS:
                report["collection_error_count"] += 1
                proc.kill()
                break
            fields = line.decode("utf-8", "replace").split()
            if fields:
                add_failed_unit(report, fields[0])
        proc.stdout.close()
        if proc.wait(timeout=5) != 0:
            report["collection_error_count"] += 1
    except (OSError, subprocess.TimeoutExpired):
        proc.kill()
        proc.wait()
        report["collection_error_count"] += 1


def encode_report(report):
    report["failed_units"] = sorted(set(report["failed_units"]))
    report["amdtee_missing_firmware"] = sorted(set(report["amdtee_missing_firmware"]))
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    while len(raw) > MAX_REPORT_BYTES and report["unknown_summaries"]:
        report["unknown_summaries"].pop()
        raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("boot health report exceeds fixed limit")
    return raw


def main():
    if sys.argv[1:] not in ([], ["--pre-inference-details"]):
        return 2
    details = sys.argv[1:] == ["--pre-inference-details"]
    if details and os.geteuid() != 0:
        return 2
    try:
        boot_id = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        boot_id = "00000000-0000-0000-0000-000000000000"
    report = empty_report(boot_id)
    if os.geteuid() != 0:
        report["collection_error_count"] += 1
    if not UUID.fullmatch(boot_id):
        report["boot_id"] = "00000000-0000-0000-0000-000000000000"
        report["collection_error_count"] += 1
    capture_journal(report, details)
    capture_failed_units(report)
    raw = encode_report(report)
    # Node OS detail mode also has bounded, sanitized pre-inference excerpts.
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
