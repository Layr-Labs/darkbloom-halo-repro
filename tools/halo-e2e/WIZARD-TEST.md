# Wi-Fi setup wizard on AMD Halo

This path reproduces the Wi-Fi-only serving boot and encrypted text inference
verified on the reference Halo. It uses the factory systemd-boot menu with
AMD Linux as the default. The reference test invoked the wizard's final action
over SSH. Use the desktop steps below to verify the launcher and buttons on
your unit. Each new Halo needs its own enrollment, calibration, and approval.

Use a dedicated lab WPA2/WPA3 Personal connection saved by NetworkManager as a
system keyfile and a synthetic text prompt. Keep signing keys on the Mac. The
wizard uses the active Wi-Fi profile on the Halo and seals its Darkbloom copy
to the approved boot. The build and calibration run without that profile. Keep
all local state, including TPM reports and receipts, in private directories
outside Git. The serving kernel and GPU stack remain trusted.

## 1. Build and install the Wi-Fi wizard image

Choose `WIFI_MODE=tpm-sealed` in
[runbook step 0](../../RUNBOOK.md#0-finish-amd-linux-first-run-setup).
Follow steps 0–3 through the signed bundle's `install` command. The shared
steps leave `WIFI_PROFILE` unset, build with a five-minute return timer, and
start the mock coordinator with zero approved releases. Keep the display and
keyboard connected. Confirm the normal boot uses the factory shim and
systemd-boot.

Continue here before the direct-shim `boot` command in step 3. Calibration
and serving use the same systemd-boot entry. Use a fresh lab setup for this
procedure. The wizard installer refuses a preexisting protected wizard.

## 2. Install the reviewed wizard helper and prepare its menu

Create a private directory on the Mac for this install's artifacts and the
fixed owner staging directory on the Halo. Check **Current Boot Loader** in
`sudo bootctl status` for systemd-boot and its **Loader** or **File** entry.
The release builder uses the exact EFI binary that the factory shim loaded.
[bootctl reference](https://www.freedesktop.org/software/systemd/man/257/bootctl.html)

```bash
# Halo
umask 077
WIZARD_STAGE="$HOME/darkbloom-halo-setup"
ESP_MOUNT=$(python3 tools/halo-e2e/device_config.py get "$DEVICE_CONFIG" esp_mount)
WIFI_IFACE=$(python3 tools/halo-e2e/device_config.py get "$DEVICE_CONFIG" wifi_iface)
install -d -m 0700 "$WIZARD_STAGE"
sudo bootctl --esp-path "$ESP_MOUNT" status
FACTORY_SDBOOT_EFI=$(sudo bootctl --esp-path "$ESP_MOUNT" --print-loader-path)
sudo cat "${FACTORY_SDBOOT_EFI:?current EFI loader path required}" \
  > "$PRIVATE_HALO_STAGE/factory-systemd-boot.efi"
sha256sum "$PRIVATE_HALO_STAGE/factory-systemd-boot.efi"
```

```bash
# Mac
umask 077
WIZARD_PRIVATE="$MAC_PRIVATE/wizard-$NEW_INSTALL_ID"
HALO_WIZARD_STAGE="/home/$OWNER_USER/darkbloom-halo-setup"
install -d -m 0700 "$WIZARD_PRIVATE"
REVIEWED_FACTORY_SDBOOT="$WIZARD_PRIVATE/factory-systemd-boot.efi"
scp "${HALO_SSH}:${HALO_STAGE}/factory-systemd-boot.efi" "$REVIEWED_FACTORY_SDBOOT"
shasum -a 256 "$REVIEWED_FACTORY_SDBOOT"
python3 tools/halo-e2e/make-wizard-archive.py --out "$WIZARD_PRIVATE/wizard.tar"
shasum -a 256 "$WIZARD_PRIVATE/wizard.tar" tools/halo-e2e/install-wizard-archive.py
scp "$WIZARD_PRIVATE/wizard.tar" tools/halo-e2e/install-wizard-archive.py \
  "${HALO_SSH}:${HALO_WIZARD_STAGE}/"
```

Compare the boot manager hash with the Halo's. Paste the two independently
recorded Mac hashes into the fixed launcher below on the Halo. It verifies
the exact installer bytes before executing them in root's isolated Python
environment. The installer independently checks the archive digest and exact
regular-file set before it writes the protected helper.

```bash
# Halo
WIZARD_INSTALLER_SHA256="REPLACE_WITH_REVIEWED_INSTALLER_SHA256"
WIZARD_ARCHIVE_SHA256="REPLACE_WITH_REVIEWED_ARCHIVE_SHA256"
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/python3 -I - "$WIZARD_STAGE/install-wizard-archive.py" \
  "$WIZARD_INSTALLER_SHA256" --archive "$WIZARD_STAGE/wizard.tar" \
  --sha256 "$WIZARD_ARCHIVE_SHA256" --owner "$OWNER_USER" \
  --release "$NEW_INSTALL_ID" --wifi-interface "$WIFI_IFACE" <<'PY'
import hashlib, os, stat, sys
path, expected = sys.argv[1:3]
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
with os.fdopen(fd, "rb") as stream:
    mode = os.fstat(stream.fileno()).st_mode
    if not stat.S_ISREG(mode):
        raise SystemExit("Expected a regular installer file")
    source = stream.read(65537)
if not 0 < len(source) <= 65536 or hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit("Wizard installer SHA-256 mismatch")
sys.argv = [path, *sys.argv[3:]]
exec(compile(source, path, "exec"), {"__name__": "__main__", "__file__": path})
PY
sudo -n /usr/local/sbin/darkbloom-halo-setup prepare-menu
sudo -n /usr/local/sbin/darkbloom-halo-setup status
sudo bootctl --esp-path "$ESP_MOUNT" list
```

Confirm the AMD Linux entry is the default, **Darkbloom** is listed, and
`status` reports `menu_ready=true` and `connected_wifi=true`. The wizard can
finish after the verified policy is armed. Save the original systemd-boot
preferences so you can restore them during cleanup.

```bash
# Halo
sudo /usr/bin/python3 -I - <<'PY' > "$WIZARD_STAGE/boot-menu-before.json"
import json
from pathlib import Path
root = Path("/sys/firmware/efi/efivars")
guid = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
values = {}
for name in ("LoaderEntryDefault", "LoaderConfigTimeout"):
    path = root / f"{name}-{guid}"
    try:
        values[name] = path.read_bytes()[4:].decode("utf-16-le").rstrip("\0")
    except FileNotFoundError:
        values[name] = None
print(json.dumps(values, indent=2))
PY
```

## 3. Collect the offline TPM calibration

In AMD Linux, read the Halo's public attestation key over your authenticated
SSH connection. Save a fresh factory quote for comparison and stage a different
fresh nonce for the offline boot. Keep the two reports private.

```bash
# Mac
ssh "$HALO_SSH" sudo -n /usr/local/sbin/darkbloom-halo-setup calibration-key \
  > "$WIZARD_PRIVATE/pinned-ak.json"
FACTORY_QUOTE_NONCE=$(openssl rand -hex 32)
ssh "$HALO_SSH" sudo -n /usr/local/sbin/darkbloom-text-e2e-control quote "$FACTORY_QUOTE_NONCE" \
  > "$WIZARD_PRIVATE/factory-quote.json"
openssl rand -hex 32 > "$WIZARD_PRIVATE/calibration-nonce"
scp "$WIZARD_PRIVATE/calibration-nonce" "${HALO_SSH}:${HALO_WIZARD_STAGE}/"
```

```bash
# Halo
sudo -n /usr/local/sbin/darkbloom-halo-setup calibrate
```

A one-second countdown starts Darkbloom automatically. This calibration boot
keeps Wi-Fi and inference off. It reads the nonce and briefly writes the public
TPM report to its dedicated directory on the EFI partition. A successful
export reboots to AMD Linux. On failure the console names the stage and the
return timer restores AMD Linux. SSH is unavailable during offline calibration.
Check the console if the Halo does not return. Make a fresh nonce for every
attempt and continue only after collecting the report from the new boot.

```bash
# Mac, after AMD Linux is back online
ssh "$HALO_SSH" sudo -n /usr/local/sbin/darkbloom-halo-setup calibration-report \
  > "$WIZARD_PRIVATE/evidence.json"
python3 - "$WIZARD_PRIVATE" <<'PY'
import base64, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
raw = (root / "evidence.json").read_bytes()
if not 0 < len(raw) <= 256 * 1024:
    raise SystemExit("Unexpected calibration report size")
offline = json.loads(raw)
factory = json.loads((root / "factory-quote.json").read_bytes())
pinned = json.loads((root / "pinned-ak.json").read_bytes())
if factory["ak_public"] != pinned["ak_public"]:
    raise SystemExit("Factory quote differs from the pinned Halo key")
for pcr in ("0", "14"):
    if offline["pcr_read_sha256"][pcr] != factory["pcr_read_sha256"][pcr]:
        raise SystemExit(f"PCR {pcr} differs from the factory reference")
log = base64.b64decode(offline["event_log"], validate=True)
if not 0 < len(log) <= 256 * 1024:
    raise SystemExit("Unexpected event log size")
(root / "reference-eventlog.bin").write_bytes(log)
PY
poc-rs/target/debug/dbrelease inspect-log \
  -in "$WIZARD_PRIVATE/reference-eventlog.bin" > "$WIZARD_PRIVATE/eventlog-summary.txt"
REVIEWED_PCR9_SHA256=$(awk '$1=="PCR" && $2=="9" && $3=="replay" {print $4}' \
  "$WIZARD_PRIVATE/eventlog-summary.txt")
printf '%s\n' "$REVIEWED_PCR9_SHA256" | grep -Eq '^[0-9a-f]{64}$'
```

The extracted log and PCR values are candidates until verification succeeds.
Review the log, Secure Boot/MOK state, the signed UKI, and the root and model
hashes from the build. Set `REVIEWED_MIN_SCRTM` on both machines to the value
in the reviewed `EV_SCRTM_VERSION` event. Back in the Halo checkout, follow
[Build the runtime template on the Halo](../../RUNBOOK.md#build-the-runtime-template-on-the-halo)
with the same worker, model, workflow and signed image. Return here after
writing the template. The Mac imports its runtime pins.

## 4. Verify the calibration and approve the mock release

Use the version and security version from the Halo template. A fresh lab can
keep the runbook's initial security version of 1. The Mac builder independently
checks the predicted factory shim → systemd-boot → UKI measurements against
the event log. The calibration verifier then checks the pinned key, fresh nonce,
full signed PCR set, and log replay before emitting a policy. If any of those
checks fails, stop and investigate using the Halo's console and private
artifacts.

```bash
# Mac, with VERSION, SVN and REVIEWED_MIN_SCRTM matching the Halo template
VERSION=0.1.0-demo
SVN=1
REVIEWED_MIN_SCRTM="SAME_REVIEWED_SCRTM_VALUE"
PRIVATE_RUNTIME_TEMPLATE="$WIZARD_PRIVATE/runtime-template.json"
scp "${HALO_SSH}:${HALO_STAGE}/runtime-template.json" "$PRIVATE_RUNTIME_TEMPLATE"
PRIVATE_MANIFEST="$WIZARD_PRIVATE/production-manifest.json"
PRIVATE_RELEASE_DSSE="$WIZARD_PRIVATE/release.dsse.json"
DBRELEASE=poc-rs/target/debug/dbrelease
"$DBRELEASE" build -channel production -version "$VERSION" -svn "$SVN" \
  -min-bios "$REVIEWED_MIN_SCRTM" \
  -uki-menu -shim "$REVIEWED_FACTORY_SHIM" -sdboot "$REVIEWED_FACTORY_SDBOOT" -uki "$SIGNED_EFI" \
  -pcr9 "$REVIEWED_PCR9_SHA256" -platform-eventlog "$WIZARD_PRIVATE/reference-eventlog.bin" \
  -runtime-from "$PRIVATE_RUNTIME_TEMPLATE" -out "$PRIVATE_MANIFEST"
```

```bash
# Mac, after the production manifest was reviewed
"$DBRELEASE" verify-calibration -in "$WIZARD_PRIVATE/evidence.json" \
  -ak-public "$WIZARD_PRIVATE/pinned-ak.json" \
  -nonce "$(cat "$WIZARD_PRIVATE/calibration-nonce")" -manifest "$PRIVATE_MANIFEST" \
  -release-id "$NEW_INSTALL_ID" > "$WIZARD_PRIVATE/expected-pcrs.json"
```

Continue after both commands succeed. Sign the exact policy with the enrolled
boot key and the release manifest with the separate coordinator release key.

```bash
# Mac
openssl dgst -sha256 -sign "$MAC_ONLY_BOOT_KEY" \
  -out "$WIZARD_PRIVATE/expected-pcrs.sig" "$WIZARD_PRIVATE/expected-pcrs.json"
"$DBRELEASE" sign -key .halo-e2e/keys/release.key \
  -in "$PRIVATE_MANIFEST" -out "$PRIVATE_RELEASE_DSSE"
"$DBRELEASE" verify -pub .halo-e2e/keys/release.pub -in "$PRIVATE_RELEASE_DSSE"
scp "$WIZARD_PRIVATE/expected-pcrs.json" "$WIZARD_PRIVATE/expected-pcrs.sig" \
  "${HALO_SSH}:${HALO_WIZARD_STAGE}/"
```

```bash
# Halo
sudo -n /usr/local/sbin/darkbloom-halo-setup arm
sudo -n /usr/local/sbin/darkbloom-halo-setup status
```

Confirm the helper reports `ready=true` and `completed=false`. The signed
policy names the exact six SHA-256 PCR values the TPM uses to release the
sealed Wi-Fi profile. The live coordinator still verifies the AMD endorsement
chain, activation of the attestation key and a fresh quote before leasing.

```bash
# Mac
install -m 0600 "$PRIVATE_RELEASE_DSSE" .halo-e2e/releases/wifi-reviewed.dsse.json
# Stop the previous coordinator in its own terminal first.
python3 poc-rs/scripts/halo-text.py coord --capture
```

Before the serving boot, run `python3 poc-rs/scripts/halo-text.py client --
providers` in the second Mac terminal and confirm there are no leased
providers. Leave the coordinator running for the timed serving boot.

## 5. Test automatic first boot and encrypted inference

In the AMD Linux desktop open **Darkbloom Setup**, choose **Use current Wi-Fi**
and then **Finish setup and restart**. Leave the keyboard alone during the
one-second countdown. To reproduce the same first boot without the desktop,
run the helper's tested final action in AMD Linux.

```bash
# Halo. Use one of the desktop or command-line entry points.
sudo -n /usr/local/sbin/darkbloom-halo-setup finish
```

On the Mac, repeat the provider listing until the reviewed release has a
lease, then follow [runbook step 5](../../RUNBOOK.md#5-verify-the-encrypted-inference-result)
with its provider ID and a new private output path.
The expected output is `halo ready` and `receipt verified`. Record the
receipt result and the exact release ID privately. For a Wi-Fi-only check
keep any Ethernet or USB network adapters disconnected. A successful run
shows that the sealed profile opened, the Halo joined Wi-Fi, and fresh
hardware TPM evidence matched the approved serving image.

Wait for the automatic return to AMD Linux after five minutes. Confirm the
six-second systemd-boot menu shows both AMD Linux and **Darkbloom**, and
allow the default to boot. In AMD Linux verify the menu and the completed
wizard state.

```bash
# Halo, in a new shell from the repository root
ESP_MOUNT=$(python3 tools/halo-e2e/device_config.py get \
  "$HOME/darkbloom-text-repro/device.json" esp_mount)
sudo -n /usr/local/sbin/darkbloom-halo-setup status
sudo bootctl --esp-path "$ESP_MOUNT" list
sudo bootctl --esp-path "$ESP_MOUNT" status
```

Record `completed=true`, both menu entries, and AMD Linux as the default and
selected entry after the return. Record whether you used the desktop launcher
or the fixed final action.

## Recovery and withdrawal

If the boot stops, select AMD Linux from the factory boot path, or allow the
return timer to finish. Record the exact console error. If the wizard reports
a calibration or policy mismatch, leave serving disabled until you have
reviewed the fresh measurements. A different boot chain, firmware state or
signed image needs a new calibration and sealing for that image.

To withdraw approval, move the wizard envelope out of the private release
directory and restart the test coordinator while Darkbloom is running.
If AMD Linux has already resumed, reboot and choose **Darkbloom** from the
systemd-boot menu after withdrawing the approval. Check the fresh coordinator
capture for an authenticated quote with `release_admitted=false` before
checking that there is no serving lease and text submission is refused. Use
the Mac client checks in [runbook step 7](../../RUNBOOK.md#7-test-release-withdrawal-and-optionally-clean-up).

```bash
# Mac
install -d -m 0700 .halo-e2e/withdrawn
mv .halo-e2e/releases/wifi-reviewed.dsse.json .halo-e2e/withdrawn/
# Stop the previous coordinator in its own terminal first.
python3 poc-rs/scripts/halo-text.py coord --capture
```

To retire wizard access on the Halo, confirm AMD Linux is the default and
the selected entry after a normal reboot. Restore the previously recorded
systemd-boot default and timeout. The commands below verify the wizard entry
belongs to your install before removing it and revoking the two grants.
The signed images and sealed test data remain available for lab review.

```bash
# Halo. Set these from this install and the recorded boot-menu-before.json.
NEW_INSTALL_ID="REPLACE_WITH_THIS_INSTALL_ID"
PREVIOUS_ENTRY_DEFAULT=""  # Use the recorded value if it was set.
PREVIOUS_MENU_TIMEOUT=""   # Use the recorded value if it was set.
WIZARD_ENTRY="$ESP_MOUNT/loader/entries/darkbloom-halo-wizard.conf"
printf 'title Darkbloom\nsort-key darkbloom\nefi /EFI/darkbloom-text/%s/grubx64.efi\n' \
  "$NEW_INSTALL_ID" | sudo cmp -s - "$WIZARD_ENTRY" &&
  sudo bootctl --esp-path "$ESP_MOUNT" set-default "$PREVIOUS_ENTRY_DEFAULT" &&
  sudo bootctl --esp-path "$ESP_MOUNT" set-timeout "$PREVIOUS_MENU_TIMEOUT" &&
  sudo rm -- "$WIZARD_ENTRY" &&
  sudo rm -- /etc/sudoers.d/darkbloom-halo-setup &&
  sudo /usr/local/sbin/darkbloom-text-e2e-control cleanup &&
  sudo bootctl --esp-path "$ESP_MOUNT" list
```
