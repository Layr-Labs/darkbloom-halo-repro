# Fixed root operations for a fresh Halo text repro

This directory contains a first-install-only, fixed-operation host controller.
The per-device inputs are public identifiers and the enrolled **public** boot
certificate. The signing private key stays on the signer. The root controller
never executes an installer, script, path, or release supplied by the ordinary
host account: it executes its own protected snapshot and accepts only the eight
signed data files in [`bundle.py`](bundle.py).
The factory Linux host needs Python 3, OpenSSL, sudo/visudo, efibootmgr,
mokutil, util-linux tools, NetworkManager, and a readable EFI variable and TPM
interface. The bootstrap checks fixed executable paths and fails before
installing its privileged helper if a prerequisite is missing.

## 1. Pin this machine on a trusted workstation

Read the hostname, owner account, ESP block device/disk/partition and GPT
PARTUUID, current host root partition PARTUUID and filesystem UUID, factory
`EFI/<vendor>` shim directory and BootOrder fallback label, and Wi-Fi interface
from the target. Check the exact DER certificate has been physically enrolled
in shim MOK and that Secure Boot is enabled. These values vary by machine;
copying another machine's values fails the bootstrap checks.
The owner account must have its passwd home at `/home/<owner_user>`; its
data-only signed release staging directory is fixed at
`/home/<owner_user>/darkbloom-text-e2e-staging`.
[`new-boot-key.sh`](../repro/new-boot-key.sh) creates a fresh signing key and
public certificate under a private output directory; physically enroll its
DER certificate before this bootstrap. Only the DER certificate enters the
bootstrap archive.

Create a new staging directory on the trusted workstation. For example:

```bash
python3 tools/halo-e2e/make-device-config.py \
  --out-dir /PRIVATE/STAGE \
  --boot-cert /PRIVATE/PUBLIC/enrolled-boot.der \
  --hostname HALO_HOSTNAME --owner-user OWNER \
  --host-partuuid HOST_ROOT_PARTUUID --host-root-uuid HOST_ROOT_FS_UUID \
  --esp-mount /efi --esp-disk /dev/nvme1n1 --esp-partition 2 \
  --esp-device /dev/nvme1n1p2 --esp-partuuid ESP_PARTUUID \
  --factory-efi-dir EFI/FACTORY_VENDOR \
  --factory-boot-label 'FACTORY BOOT LABEL' --wifi-iface WIFI_IFACE
python3 tools/halo-e2e/make-bootstrap-archive.py \
  --inputs /PRIVATE/STAGE/inputs --output /PRIVATE/STAGE/bootstrap.tar
```

The first command stages exactly `inputs/device.json` and
`inputs/boot-cert.der`. The second packages exactly ten fixed source/input
files and prints the archive SHA-256. It accepts no secret file or signer key.
Review the archive and keep its digest separately from the Halo transfer. The
config schema is strict and rejects unknown fields, shell metacharacters in
identity fields, path traversal, and mismatched ESP disk/partition names.

## 2. Verify once, then execute only root-owned extracted bytes

Copy `bootstrap.tar` to the target's ordinary account. Set `EXPECTED` to the
digest recorded on the trusted workstation. Paste this fixed root entrypoint
in the target terminal. It hashes the same bytes it parses, checks the exact
archive member set and regular-file types, and writes a new root-private tree
before running the bootstrap. Do not run a helper from an owner-writable
checkout through sudo.

```bash
ARCHIVE=/home/OWNER/bootstrap.tar
EXPECTED=64_LOWERCASE_HEX_FROM_TRUSTED_WORKSTATION
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/python3 -I - "$ARCHIVE" "$EXPECTED" <<'PY'
import hashlib, io, os, pathlib, shutil, stat, subprocess, sys, tarfile, tempfile
path, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
    raise SystemExit('Invalid expected archive digest')
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4 * 1024 * 1024:
        raise SystemExit('Invalid archive file')
    with os.fdopen(fd, 'rb', closefd=False) as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit('Archive SHA-256 mismatch')
names = {
    'tools/halo-e2e/bootstrap.sh', 'tools/halo-e2e/control.py',
    'tools/halo-e2e/bundle.py', 'tools/halo-e2e/device_config.py',
    'tools/halo-e2e/check-mok.py', 'tools/tpm/read_ek_chain.py',
    'tools/tpm/collect_quote.py', 'nodeos/text/install.sh',
    'inputs/device.json', 'inputs/boot-cert.der',
}
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
    members = archive.getmembers()
    if len(members) != len(names) or {m.name for m in members} != names or any(not m.isfile() or m.size > 2 * 1024 * 1024 for m in members):
        raise SystemExit('Unexpected bootstrap archive member')
    root = pathlib.Path(tempfile.mkdtemp(prefix='.darkbloom-reviewed-', dir='/var/lib'))
    try:
        for member in members:
            target = root / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.name in {'tools/halo-e2e/bootstrap.sh', 'nodeos/text/install.sh'} else 0o600)
        subprocess.run(['/usr/bin/bash', str(root / 'tools/halo-e2e/bootstrap.sh')], check=True)
    finally:
        shutil.rmtree(root)
PY
```

The protected bootstrap checks the config against the live hostname, ESP
mount/partition UUID, host filesystem UUID, enrolled MOK runtime variable,
Secure Boot state, and factory shim files. It stages code, public trust,
BootOrder and EFI file baselines, tests the fixed helper and sudoers rule,
then grants only the configured owner account. A preexisting installation or
unknown partial state is refused. It never reboots or creates an EFI entry.
The exact MOK parser is included in this export as [`check-mok.py`](check-mok.py)
and has no runtime dependency on an earlier lab PoC.

## 3. Build, sign, and install the data-only release

The fixed helper provides these operations:

| Operation | Effect |
| --- | --- |
| `status` | Public BootOrder and installed release state |
| `ek-chain` | Public TPM EK certificate chain as base64 JSON |
| `quote <64hex>` | Fresh diagnostic TPM quote including PCR 11 |
| `wifi-profile` | Active pinned Wi-Fi keyfile, before first install only |
| `install` | Verify signed eight-file bundle and stage an EFI entry, no reboot |
| `boot` | Verify installed bytes, set only this entry's BootNext, reboot once |
| `cleanup` | Verify factory baseline, restore recognized fallback order, revoke this sudo grant |

`wifi-profile` contains the network credential. Redirect it **directly** to a
private 0600 file outside Git and transcripts. The Node OS builder requires
that private file, a private pairing token, model weights, a compatible Linux
`dbnode`, and the coordinator CA. See
[`nodeos/text/README.md`](../../nodeos/text/README.md) for the rootless build
and the trusted signer workflow. Keep EK certificate files out of Git as
device identifiers.

The owner places the exact eight files named in [`bundle.py`](bundle.py) under
their fixed staging directory, creates the canonical manifest with
`make-bundle.py --sequence N STAGING`, and has the trusted signer sign those
exact manifest bytes with the enrolled boot key. The helper verifies the
signature, streams the eight files from open descriptors into root-private
storage, then executes its protected installer. Sequence numbers strictly
increase; failed accepted installs consume a sequence. The helper rejects
unknown EFI file drift, unrelated BootNext changes, and UKI sidecars.

Run host-only tests with `python3 -B -m unittest discover -s tools/halo-e2e`.
They use temporary files and ephemeral test certificates and never access a
real TPM, EFI variables, sudo, the target disk, or a signing key.
