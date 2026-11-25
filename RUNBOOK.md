# Set up a fresh Halo for Darkbloom dual boot and mock inference

Run the commands labelled **Mac** on the trusted coordinator/signing machine and
those labelled **Halo** in its normal Linux OS as the ordinary owner account.
Use a fresh checkout on both machines and compare `git rev-parse HEAD`.
Use the ordinary source checkout permissions from `umask 022`; the commands
below create separate private directories for keys, models and images.
Start with the [prerequisites](README.md#requirements).

Start with sections 0–3. Choose the path you want to test in section 0.

- **Wi-Fi wizard** (`tpm-sealed`) follows the
  [wizard test](tools/halo-e2e/WIZARD-TEST.md) after signed installation. The
  reference Halo passed offline TPM calibration, automatic first boot over
  Wi-Fi, and encrypted inference with a verified receipt. We invoked the
  wizard's final action over SSH. Use the desktop wizard to test the click-through.
- **Direct shim and firmware picker** (`embedded`) continues through sections
  3–7. The reference Halo completed the one-time signed inference demo. Section 6
  tests the firmware picker on your unit with AMD Linux as the default.

Use synthetic prompts and a dedicated WPA2/WPA3 Personal lab Wi-Fi profile
saved system-wide by NetworkManager. The direct shim path stores the profile
in its private image. The wizard seals its copy to the measured Darkbloom
boot on the Halo. The serving kernel and GPU stack remain trusted.

Commands below use placeholders. Keep actual device UUIDs, LAN addresses,
EK material, Wi-Fi keyfiles, pairing/API tokens, event logs, signing keys,
prompts, and outputs in private storage or the ignored `.halo-e2e/` directory.
Keep them out of commits. `nodeos/text/README.md` and the
linked tools define the current accepted input formats. Run every rootless
build command as the ordinary Halo user, and use the fixed root controller
only for the listed install/boot/cleanup operations.

## 0. Finish AMD Linux first-run setup

1. Connect a monitor and keyboard. Finish factory Linux setup and its required
   updates, then reboot into AMD Linux.
2. Join the Halo and Mac to the same reachable lab Wi-Fi network. Use the
   **Remote Access** page in AMD Ryzen AI Developer Center to find the Halo's
   address and owner account. On a first SSH connection, compare the host
   fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the
   Halo console. This demo can run entirely over Wi-Fi.
3. For the Wi-Fi wizard, install the Halo prerequisites below in AMD Linux.
   Finish package configuration and reboot back into AMD Linux before taking
   the factory boot baseline in section 1.

See the [AMD Ryzen AI Halo User Guide](https://developer.amd.com/playbooks/user-guide/).

```bash
# Halo, for the Wi-Fi wizard
sudo apt-get update
sudo apt-get install --no-install-recommends tpm2-tools python3-cryptography zenity
```

```bash
# Halo
uname -r
dpkg --audit
dpkg-query -W systemd libsystemd-shared llama.cpp-tools libggml0-backend-hip amd64-microcode
test -r "/boot/vmlinuz-$(uname -r)"
test -d "/usr/lib/modules/$(uname -r)"
sudo mokutil --sb-state
ls -l /dev/tpmrm0
findmnt -no SOURCE,FSTYPE,FSROOT -T /var/lib
df -h "$HOME" /var/lib
podman info --format '{{.Host.Security.Rootless}}'
```

The reference used RAH-002, vendor kernel `7.2.7+rex-amd64`, systemd
`257.13-1~deb13u1`, Secure Boot, Pluton TPM, rootless Podman and Btrfs
top-level subvolume 5. Check that `dpkg --audit` reports no pending package
configuration and the `/var/lib` check reports Btrfs with `FSROOT` set to `/`.
See [requirements](README.md#requirements). If the
installed systemd ABI or storage layout differs, have the matching build and
device configuration reviewed before continuing.

Use private paths such as these from the respective checkout roots. Transfer
the actual values directly between the two machines and keep them out of Git.
After a Halo reboot, return to the checkout and rerun the Halo variable block
with the same values. Repeat the Mac block when opening its second terminal.

```bash
# Mac, from this repository root:
umask 077
export HALO_SSH="OWNER@HALO_ADDRESS"
export OWNER_USER="HALO_OWNER_ACCOUNT"
export MAC_LAN_IPV4="MAC_LAN_ADDRESS"
export NEW_INSTALL_ID=text-demo-001
export MAC_PRIVATE="$PWD/.halo-e2e/repro-state"
export PRIVATE_BOOTSTRAP_STAGE="$MAC_PRIVATE/bootstrap"
export HALO_STAGE="/home/$OWNER_USER/darkbloom-text-repro"
mkdir -p "$PRIVATE_BOOTSTRAP_STAGE"
chmod 0700 "$MAC_PRIVATE" "$PRIVATE_BOOTSTRAP_STAGE"
ssh "$HALO_SSH" hostname
rustc --version
docker info --format '{{.ServerVersion}}'
```

```bash
# Halo, from this repository root as its ordinary user:
umask 077
export MAC_LAN_IPV4="SAME_MAC_LAN_ADDRESS"
export NEW_INSTALL_ID=text-demo-001
export NEXT_SEQUENCE=1
export VERSION=0.1.0-demo
export SVN=1
export OWNER_USER=$(id -un)
export PRIVATE_HALO_STAGE="$HOME/darkbloom-text-repro"
export PRIVATE_HALO_MODEL="$PRIVATE_HALO_STAGE/model"
export HALO_STAGING="/home/$OWNER_USER/darkbloom-text-e2e-staging"
export NODEOS_TEXT_WORK="$PRIVATE_HALO_STAGE/image-work"
export WIFI_MODE=tpm-sealed   # Set embedded here for the direct shim path.
install -d -m 0700 "$PRIVATE_HALO_STAGE" "$PRIVATE_HALO_MODEL" "$HALO_STAGING"
```

For device identity inputs below, use fresh local inventory. For release
inputs, `SIGNED_EFI` is the signed UKI copied to each machine,
`FACTORY_SHIM`/`REVIEWED_FACTORY_SHIM` are copies of the same factory shim,
and `PRIVATE_RUNTIME_TEMPLATE` is transferred from the Halo to the Mac for
review. Set each path explicitly on the machine running that command.

## 1. Establish a boot signer and device pins

On the Halo, inspect these values before filling the Mac-side device config:

```bash
hostname
id -un
lsblk -o NAME,PKNAME,PARTUUID,UUID,FSTYPE,MOUNTPOINTS
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt --types vfat
sudo efibootmgr -v
nmcli device status
```

Copy the public values into the Mac shell: `HALO_HOSTNAME`, `OWNER_USER`,
`HOST_PARTUUID` and `HOST_ROOT_UUID` for the root Btrfs partition;
`ESP_MOUNT`, `ESP_DEVICE`, `ESP_DISK`, `ESP_PARTITION` and `ESP_PARTUUID`
for the mounted EFI partition; `FACTORY_EFI_DIR` and `FACTORY_BOOT_LABEL`
from its shim boot entry, using a path such as `EFI/<vendor>` for
`FACTORY_EFI_DIR`; and `WIFI_IFACE` for the connected wireless device.
The factory EFI directory must contain `shimx64.efi` and `mmx64.efi`.
Use the following commands on the Halo after setting `ESP_DEVICE` and
`ESP_MOUNT`. Allow room for the new UKI, shim and MokManager plus the
installer's 16 MiB free-space margin.

```bash
esp_node=$(basename "$(readlink -f "$ESP_DEVICE")")
cat "/sys/class/block/$esp_node/partition"  # ESP_PARTITION
df -Pk "$ESP_MOUNT"
```

Confirm the factory AMD Linux entry is first in `BootOrder`. Record that
order before any Darkbloom install.

On a fresh machine, generate a new Secure Boot signing key **off the Halo**:

```bash
bash tools/repro/new-boot-key.sh --out "$MAC_PRIVATE/new-boot-key"
export ENROLLED_CERT_DER="$MAC_PRIVATE/new-boot-key/boot-cert.der"
export ENROLLED_CERT_PEM="$MAC_PRIVATE/new-boot-key/boot-cert.pem"
export MAC_ONLY_BOOT_KEY="$MAC_PRIVATE/new-boot-key/boot-signing.key"
```

Transfer only the public DER certificate from the Mac, then enroll it on
the Halo.

```bash
# Mac
scp "$ENROLLED_CERT_DER" "${HALO_SSH}:boot-cert.der"
```

```bash
# Halo
PUBLIC_BOOT_CERT_DER="$HOME/boot-cert.der"  # transfer only the public DER here
sudo mokutil --import "$PUBLIC_BOOT_CERT_DER"
sudo reboot
```

At the Halo console, choose **Enroll MOK**, continue, confirm with the
enrollment password just set, and choose **Reboot**. Back in AMD Linux, run
`sudo mokutil --test-key "$HOME/boot-cert.der"` and `mokutil --sb-state`.
Run `sudo efibootmgr -v` again and check that AMD Linux remains first.
Continue after the key is enrolled and Secure Boot is enabled. Keep the private
key on the Mac. Review and pin the certificate's DER SHA-256 in the signer
and root bootstrap before
using a different key. Keep the factory shim, firmware trust, and original
boot order as baseline evidence. The helper's protected bootstrap is not a
generic sudo grant and must be adapted to the target's device paths.

Stage a private `device.json` and public boot certificate for the reviewed
root-owned bootstrap archive; replace every placeholder with independently
checked values from this machine:

```bash
python3 tools/halo-e2e/make-device-config.py \
  --out-dir "$PRIVATE_BOOTSTRAP_STAGE" --boot-cert "$ENROLLED_CERT_DER" \
  --hostname "$HALO_HOSTNAME" --owner-user "$OWNER_USER" \
  --host-partuuid "$HOST_PARTUUID" --host-root-uuid "$HOST_ROOT_UUID" \
  --esp-mount "$ESP_MOUNT" --esp-device "$ESP_DEVICE" \
  --esp-partuuid "$ESP_PARTUUID" --esp-disk "$ESP_DISK" \
  --esp-partition "$ESP_PARTITION" \
  --factory-efi-dir "$FACTORY_EFI_DIR" \
  --factory-boot-label "$FACTORY_BOOT_LABEL" --wifi-iface "$WIFI_IFACE"
python3 tools/halo-e2e/make-bootstrap-archive.py \
  --inputs "$PRIVATE_BOOTSTRAP_STAGE/inputs" \
  --output "$PRIVATE_BOOTSTRAP_STAGE/bootstrap.tar"
scp "$PRIVATE_BOOTSTRAP_STAGE/bootstrap.tar" "${HALO_SSH}:bootstrap.tar"
```

The second command hashes an archive containing this input plus the exact
`tools/halo-e2e/{bootstrap.sh,control.py,bundle.py,device_config.py,check-mok.py}`,
`nodeos/text/install.sh`, and `tools/tpm/{read_ek_chain.py,collect_quote.py}`
sources. The owner checks the separately communicated hash **before** running
the [fixed root archive entrypoint](tools/halo-e2e/README.md#2-verify-once-then-execute-only-root-owned-extracted-bytes).
That entrypoint extracts only the ten reviewed regular files into a new
root-owned, non-writable directory and runs `bootstrap.sh` once. The
bootstrap checks the enrolled MOK, ESP and factory boot state before adding
the narrowly scoped `/usr/local/sbin/darkbloom-text-e2e-control` grant.
Inspect `sudo /usr/local/sbin/darkbloom-text-e2e-control status`; do not run
owner-writable source files as root. The helper accepts only `status`,
`ek-chain`, `quote <64hex>`, `wifi-profile` (before first install), `install`,
`boot`, `enable-dual-boot`, `disable-dual-boot`, and `cleanup`.

## 2. Start the Mac-side mock coordinator and build the image

Transfer these files privately as the steps below produce them. Set each path
variable on the machine where it is used; the two shells do not share variables.
Never transfer the boot or release signing private keys to the Halo.

| Direction | Files / destination |
| --- | --- |
| Mac → Halo | `inputs/device.json` → `$PRIVATE_HALO_STAGE/device.json`; bootstrap archive → owner's home |
| Mac → Halo | `.halo-e2e/tls/ca.pem` → `$PRIVATE_HALO_STAGE/ca.pem`; `.halo-e2e/provider-token` → `$PRIVATE_HALO_STAGE/pairing-token` |
| Halo → Mac | `$NODEOS_TEXT_WORK/out/unsigned.efi` → `$UNSIGNED_EFI`; factory `shimx64.efi` → `$REVIEWED_FACTORY_SHIM` |
| Mac → Halo | Signed EFI and SHA-256 file → `$SIGNED_EFI` and `$SIGNED_EFI_SHA256` |
| Halo → Mac → Halo | Bundle `manifest.json` → `$MAC_PRIVATE/manifest.json`; signed `manifest.sig` → `$HALO_STAGING/manifest.sig` |
| Halo → Mac | Runtime template → `$MAC_PRIVATE/runtime-template.json` |

Keep credential files mode `0600` and staging directories `0700`.

On the Halo, set `ESP_MOUNT` and `FACTORY_EFI_DIR` from step 1 and copy the
factory shim into the owner's private stage. Compare its digest after
transferring it to the Mac.

```bash
# Halo
FACTORY_SHIM="$PRIVATE_HALO_STAGE/factory-shimx64.efi"
sudo cat "$ESP_MOUNT/$FACTORY_EFI_DIR/shimx64.efi" >"$FACTORY_SHIM"
sha256sum "$FACTORY_SHIM"
```

Build the current Rust binaries from a frozen source revision and record
their SHA-256. The Mac runner stores credentials and captures in ignored
`.halo-e2e/` with private permissions. It creates a TLS 1.3 certificate for
both localhost and the Mac's LAN IP; local clients pin its CA. The Halo
connects directly over LAN WSS with the same pinned CA.

```bash
cargo build --manifest-path poc-rs/Cargo.toml --locked -p db-cli --bins
python3 poc-rs/scripts/halo-text.py init --lan-ip "$MAC_LAN_IPV4"
# Keep the mock coordinator running in this terminal.
python3 poc-rs/scripts/halo-text.py coord --capture
```

Use a second Mac terminal in the same checkout for signing and the client.
Define the Mac path variables there too. The fresh coordinator should report
zero approved releases. Allow incoming TCP 8790 for the mock coordinator on
the Mac while keeping its firewall on.

```bash
# Mac
REVIEWED_FACTORY_SHIM="$MAC_PRIVATE/factory-shimx64.efi"
scp "${HALO_SSH}:${HALO_STAGE}/factory-shimx64.efi" "$REVIEWED_FACTORY_SHIM"
shasum -a 256 "$REVIEWED_FACTORY_SHIM"
scp "$PRIVATE_BOOTSTRAP_STAGE/inputs/device.json" "${HALO_SSH}:${HALO_STAGE}/device.json"
scp .halo-e2e/tls/ca.pem "${HALO_SSH}:${HALO_STAGE}/ca.pem"
scp .halo-e2e/provider-token "${HALO_SSH}:${HALO_STAGE}/pairing-token"
```

On the Halo, build fresh compatible `dbnode` and `dbrelease` binaries from
the same frozen source using the rootless pinned Rust/Alpine image. The
[`build-linux.sh`](tools/repro/build-linux.sh) wrapper fetches locked
dependencies into a private ordinary-user cache, then builds offline with
container networking disabled. It emits SHA-256 records for both outputs.
Copy the Mac TLS CA to the Halo's
private staging area with the private provider pairing-token file from the
Mac. Prepare one approved GGUF model and the fixed `nodeos/text/workflow.json`.

```bash
# Halo ordinary user, after the fixed root bootstrap has been installed:
umask 077
install -d -m 0700 "$PRIVATE_HALO_STAGE"
chmod 0600 "$PRIVATE_HALO_STAGE/pairing-token"
curl --fail --silent --show-error --cacert "$PRIVATE_HALO_STAGE/ca.pem" \
  "https://${MAC_LAN_IPV4}:8790/v1/coordinator" >/dev/null
case "$WIFI_MODE" in
  tpm-sealed) unset WIFI_PROFILE ;;
  embedded)
    export WIFI_PROFILE="$PRIVATE_HALO_STAGE/nodeos.nmconnection"
    sudo /usr/local/sbin/darkbloom-text-e2e-control wifi-profile >"$WIFI_PROFILE"
    chmod 0600 "$WIFI_PROFILE"
    ;;
esac
```

For the Wi-Fi wizard, leave `WIFI_PROFILE` unset throughout the build. For the
direct shim path, keep the exported keyfile in the private Halo directory.

For the recorded model, obtain the public
[Unsloth Qwen3-Coder GGUF revision](https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/tree/b17cb02dd882d5b6ab62fc777ad2995f19668350)
on the Halo as an ordinary user; no weights are bundled here. Review the
model's terms and verify the complete file before `prepare`:

```bash
mkdir -p "$PRIVATE_HALO_MODEL"
curl --fail --location \
  --output "$PRIVATE_HALO_MODEL/model.gguf" \
  'https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/b17cb02dd882d5b6ab62fc777ad2995f19668350/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf'
printf '%s  %s\n' \
  'fadc3e5f8d42bf7e894a785b05082e47daee4df26680389817e2093056f088ad' \
  "$PRIVATE_HALO_MODEL/model.gguf" | sha256sum --check
```

The pinned file is 18,556,689,568 bytes.

On the Halo, the text builder computes the model hash, pins installed package
versions, builds the root and model verity trees, and constructs the unsigned
UKI. The required systemd patch is a matched core/executor pair; the rootless
test proves `RestrictFileSystems=` fails closed under a synthetic
confidentiality command line. The network-policy test uses a disposable
Podman network namespace and never edits the host firewall.

```bash
export DEVICE_CONFIG="$PRIVATE_HALO_STAGE/device.json"  # reviewed copy of inputs/device.json
export HALO_STAGING="/home/$OWNER_USER/darkbloom-text-e2e-staging"
bash tools/repro/build-linux.sh --work "$PRIVATE_HALO_STAGE/rust-build"
export AGENT="$PRIVATE_HALO_STAGE/rust-build/target/release/dbnode"
export HALO_DBRELEASE="$PRIVATE_HALO_STAGE/rust-build/target/release/dbrelease"
export COORDINATOR="wss://$MAC_LAN_IPV4:8790/v1/provider/ws"
export CA_CERT="$PRIVATE_HALO_STAGE/ca.pem"
export PAIRING_TOKEN_FILE="$PRIVATE_HALO_STAGE/pairing-token"
export TEXT_MODEL="$PRIVATE_HALO_MODEL/model.gguf"
export TEXT_MODEL_ID=qwen3-coder-30b-a3b-instruct-q4-k-m
if [ "$WIFI_MODE" = tpm-sealed ]; then export RETURN_AFTER=5min; fi
bash nodeos/text/scripts/build-patched-systemd-core.sh "$PRIVATE_HALO_STAGE/systemd-build"
bash nodeos/text/scripts/test-patched-systemd-core.sh "$PRIVATE_HALO_STAGE/systemd-build/artifacts/libsystemd-core-257.so"
export SYSTEMD_CORE="$PRIVATE_HALO_STAGE/systemd-build/artifacts/libsystemd-core-257.so"
bash nodeos/text/build.sh prepare
bash nodeos/text/build.sh rootfs
bash nodeos/text/scripts/test-network-policy.sh
bash nodeos/text/build.sh models
bash nodeos/text/build.sh initrd
ID="$NEW_INSTALL_ID" bash nodeos/text/build.sh options
bash nodeos/text/build.sh uki
```

`ID` and the bundle sequence must be new and monotonic. The builder requires
an explicit, reviewed device configuration and pins the factory kernel and
package versions; do not transplant a prior image. Review `$NODEOS_TEXT_WORK/out/options`, the root and
model hashes, image contents, `build-inputs.json`, and the unsigned UKI
sections before signing. The initrd checker must find the signed SHA-384
module and narrow early loader. Debug, external journal export, and free-form
agent arguments are rejected by the text profile.

## 3. Sign, install, and take a calibration capture

Transfer `$NODEOS_TEXT_WORK/out/unsigned.efi` to the Mac signer. Sign with the
enrolled private key in its isolated, pinned signer environment, verify the
signature against the pinned public certificate, and return `signed.efi`
plus `signed.efi.sha256` to the Halo staging `out/`. The signer refuses an
already-signed, multi-profile or unexpected UKI. The private key never goes
to the Halo.

```bash
# Mac only: the private boot key is mounted read-only into the signer container.
UNSIGNED_EFI="$MAC_PRIVATE/unsigned.efi"
scp "${HALO_SSH}:${HALO_STAGE}/image-work/out/unsigned.efi" "$UNSIGNED_EFI"
ENROLLED_CERT_DER_SHA256=$(cat "$MAC_PRIVATE/new-boot-key/boot-cert.sha256")
NEW_PRIVATE_SIGN_DIR="$MAC_PRIVATE/signed-$NEW_INSTALL_ID"
docker pull 'debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4'
bash poc-rs/scripts/sign-text-uki.sh --unsigned "$UNSIGNED_EFI" \
  --out "$NEW_PRIVATE_SIGN_DIR" --cert "$ENROLLED_CERT_PEM" \
  --key "$MAC_ONLY_BOOT_KEY" --cert-sha256 "$ENROLLED_CERT_DER_SHA256"
SIGNED_EFI="$NEW_PRIVATE_SIGN_DIR/signed.efi"
scp "$SIGNED_EFI" "$NEW_PRIVATE_SIGN_DIR/signed.efi.sha256" "${HALO_SSH}:${HALO_STAGE}/"
```

On the Halo, stage the eight data files after the signed UKI and its hash
record arrive in the private directory.

```bash
SIGNED_EFI="$PRIVATE_HALO_STAGE/signed.efi"
SIGNED_EFI_SHA256="$PRIVATE_HALO_STAGE/signed.efi.sha256"
install -d -m 0700 "$HALO_STAGING/out"
cp --reflink=auto "$NODEOS_TEXT_WORK"/out/{root.erofs,root.verity,models.erofs,models.verity,payload.sha256,install-id} \
  "$HALO_STAGING/out/"
install -m 0600 "$SIGNED_EFI" "$HALO_STAGING/out/signed.efi"
install -m 0600 "$SIGNED_EFI_SHA256" "$HALO_STAGING/out/signed.efi.sha256"
python3 tools/halo-e2e/make-bundle.py --sequence "$NEXT_SEQUENCE" "$HALO_STAGING"
```

Transfer only `manifest.json` to the Mac, sign it there, and return
`manifest.sig` to the fixed Halo staging directory:

```bash
HALO_BUNDLE="/home/$OWNER_USER/darkbloom-text-e2e-staging"
scp "${HALO_SSH}:${HALO_BUNDLE}/manifest.json" "$MAC_PRIVATE/manifest.json"
openssl dgst -sha256 -sign "$MAC_ONLY_BOOT_KEY" \
  -out "$MAC_PRIVATE/manifest.sig" "$MAC_PRIVATE/manifest.json"
scp "$MAC_PRIVATE/manifest.sig" "${HALO_SSH}:${HALO_BUNDLE}/manifest.sig"
```

Stage exactly the eight data files named in
[`tools/halo-e2e/README.md`](tools/halo-e2e/README.md) plus the canonical
bundle manifest and its signature. The root controller verifies signature,
sequence, file names, hashes, factory files and boot state; it
never accepts replacement executable code in a bundle. `install` does not
reboot. `boot` verifies again, sets its own BootNext, and performs one reboot
without changing the factory default BootOrder.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control install
```

**Wi-Fi wizard.** Continue with the
[wizard test](tools/halo-e2e/WIZARD-TEST.md) from this signed install. Its
offline calibration and serving boot use the same systemd-boot menu entry.

**Direct shim.** Continue here with the protected one-time boot.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control boot
```

With no matching **production** release, the mock coordinator must refuse a
lease while `--capture` records the authenticated EK/AK proof, fresh quote,
and event log in private `.halo-e2e/captures/`. The capture is not permission
to serve. The machine's return timer should restore the owner's boot;
verify status after the return.

## 4. Review the reference and approve a production release

Extract a reference log from a capture only after checking that it reports
`pre_release_verified=true`, `ak_activated=true`, and PCR 11 in the expected
selection. Review the source and built image, Secure Boot/MOK state, event log and image contents. Check that the captured PCRs describe the image
you built and signed before approving it.

```bash
# Mac. Choose the fresh capture written during this unit's first Darkbloom boot.
find .halo-e2e/captures -type f -name '*.json' -print
PRIVATE_CAPTURE_JSON=".halo-e2e/captures/REPLACE_WITH_FRESH_CAPTURE_FILENAME.json"
PRIVATE_REFERENCE_EVENTLOG="$MAC_PRIVATE/reference-eventlog.bin"
python3 poc-rs/scripts/halo-text.py extract-capture "$PRIVATE_CAPTURE_JSON" \
  --out "$PRIVATE_REFERENCE_EVENTLOG"
poc-rs/target/debug/dbrelease inspect-log -in "$PRIVATE_REFERENCE_EVENTLOG" \
  | tee "$MAC_PRIVATE/eventlog-summary.txt"
REVIEWED_PCR9_SHA256=$(awk '$1=="PCR" && $2=="9" && $3=="replay" {print $4}' \
  "$MAC_PRIVATE/eventlog-summary.txt")
printf '%s\n' "$REVIEWED_PCR9_SHA256" | grep -Eq '^[0-9a-f]{64}$'
```

To avoid copying a large GGUF to the Mac, make one **dev UKI manifest
template** on the Halo from the already-hashed model and exact `dbnode`,
then review it on the Mac. Its placeholder PCR 9 is not trusted for
production; `-runtime-from` imports only the pinned runtime fields. It
cannot be combined with `-agent`, `-engine`, `-models-dir`, `-hash-cache`, or
the `-text-*` flags in the production build.
Set `REVIEWED_MIN_SCRTM` from the reviewed `EV_SCRTM_VERSION` event under
PCR 0 in the summary. The reference RAH-002 value was `MFGB0.04.00`.
Use the measured value from your unit in both shells.

### Build the runtime template on the Halo

After a reboot, restore the Halo variables from section 0 first. Use the same
worker, model, workflow and signed image from sections 2–3.

```bash
# Halo ordinary user, using the freshly built Linux dbrelease binary:
AGENT="$PRIVATE_HALO_STAGE/rust-build/target/release/dbnode"
HALO_DBRELEASE="$PRIVATE_HALO_STAGE/rust-build/target/release/dbrelease"
FACTORY_SHIM="$PRIVATE_HALO_STAGE/factory-shimx64.efi"
SIGNED_EFI="$PRIVATE_HALO_STAGE/signed.efi"
TEXT_MODEL="$PRIVATE_HALO_MODEL/model.gguf"
TEXT_MODEL_ID=qwen3-coder-30b-a3b-instruct-q4-k-m
REVIEWED_MIN_SCRTM="REPLACE_WITH_REVIEWED_SCRTM_VALUE"
ZERO64=$(printf '%064d' 0)  # dev template only; never a production PCR 9
PRIVATE_RUNTIME_TEMPLATE="$PRIVATE_HALO_STAGE/runtime-template.json"
"$HALO_DBRELEASE" build -channel dev -version "$VERSION" -svn "$SVN" \
  -min-bios "$REVIEWED_MIN_SCRTM" \
  -shim "$FACTORY_SHIM" -uki "$SIGNED_EFI" -pcr9 "$ZERO64" \
  -agent "$AGENT" -text-model-id "$TEXT_MODEL_ID" \
  -text-model "$TEXT_MODEL" -text-workflow nodeos/text/workflow.json \
  -out "$PRIVATE_RUNTIME_TEMPLATE"
```

### Approve the direct shim release on the Mac

```bash
# Mac signer, after transferring and reviewing the dev template:
export VERSION=0.1.0-demo
export SVN=1
REVIEWED_MIN_SCRTM="SAME_REVIEWED_SCRTM_VALUE"
PRIVATE_RUNTIME_TEMPLATE="$MAC_PRIVATE/runtime-template.json"
scp "${HALO_SSH}:${HALO_STAGE}/runtime-template.json" "$PRIVATE_RUNTIME_TEMPLATE"
PRIVATE_MANIFEST="$MAC_PRIVATE/production-manifest.json"
PRIVATE_RELEASE_DSSE="$MAC_PRIVATE/release.dsse.json"
MAC_ONLY_RELEASE_KEY="$PWD/.halo-e2e/keys/release.key"
RELEASE_PUBLIC_KEY="$PWD/.halo-e2e/keys/release.pub"
poc-rs/target/debug/dbrelease build -channel production -version "$VERSION" -svn "$SVN" \
  -min-bios "$REVIEWED_MIN_SCRTM" \
  -shim "$REVIEWED_FACTORY_SHIM" -uki "$SIGNED_EFI" \
  -pcr9 "$REVIEWED_PCR9_SHA256" \
  -platform-eventlog "$PRIVATE_REFERENCE_EVENTLOG" \
  -runtime-from "$PRIVATE_RUNTIME_TEMPLATE" \
  -out "$PRIVATE_MANIFEST"
poc-rs/target/debug/dbrelease sign -key "$MAC_ONLY_RELEASE_KEY" -in "$PRIVATE_MANIFEST" \
  -out "$PRIVATE_RELEASE_DSSE"
poc-rs/target/debug/dbrelease verify -pub "$RELEASE_PUBLIC_KEY" -in "$PRIVATE_RELEASE_DSSE"
```

The production builder independently derives PCR 4/11 from the signed UKI,
checks PCR 4/9/11/12 against the reference log, and pins PCR 0/7/14.
Publish the reviewed DSSE envelope to the mock coordinator's private
`releases/` directory and restart it. The worker must pass fresh attestation against this signed release before it receives a lease.

```bash
install -m 0600 "$PRIVATE_RELEASE_DSSE" .halo-e2e/releases/text-reviewed.dsse.json
# Stop the old mock coordinator, then start it again with the same private state:
python3 poc-rs/scripts/halo-text.py coord --capture
```

The calibration boot returns to the owner's OS on its timer. After the
coordinator has restarted with the reviewed release, invoke the fixed Halo
controller for **a new one-shot sealed boot**. Its fresh quote must pass before a lease appears.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control status
sudo /usr/local/sbin/darkbloom-text-e2e-control boot
```

## 5. Verify the encrypted inference result

Only after a lease is visible, use the Mac client with its pinned TLS CA,
AMD anchors, release signer and coordinator log key. `text` independently
verifies the provider and seals the prompt to its TPM-bound key. It verifies
the returned receipt before creating a private output file.

```bash
PRIVATE_PROMPT_FILE="$MAC_PRIVATE/prompt.txt"
PRIVATE_NEW_OUTPUT="$MAC_PRIVATE/response.txt"  # must not already exist
printf 'Reply with exactly: halo ready\n' >"$PRIVATE_PROMPT_FILE"
python3 poc-rs/scripts/halo-text.py client -- providers
# Set PROVIDER_ID to the leased Halo listed above.
python3 poc-rs/scripts/halo-text.py client -- verify "$PROVIDER_ID"
python3 poc-rs/scripts/halo-text.py client -- text \
  -provider "$PROVIDER_ID" -prompt-file "$PRIVATE_PROMPT_FILE" \
  -max-tokens 64 -out "$PRIVATE_NEW_OUTPUT"
```

Success: the command exits zero, prints `receipt verified`, and creates the
response text file with mode `0600`. Read it locally; the coordinator routes the
sealed request and result. An unknown release or failed fresh proof must not receive a lease.

## 6. Enable and test the firmware boot picker

After the one-time inference check passes and the Halo returns to AMD Linux,
run these commands on the Halo. The helper verifies the signed release and
appends exactly its direct shim entry to the saved firmware order.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control status
sudo /usr/local/sbin/darkbloom-text-e2e-control enable-dual-boot
sudo efibootmgr -v
```

1. Confirm the original factory order is still the prefix and its first entry
   is AMD Linux. The last entry should be the installed **Darkbloom Text Node OS**
   for your install ID.
2. Restart normally once and confirm AMD Linux still starts.
3. Restart again and open the Halo firmware's one-time boot picker using the
   startup key for your firmware. Select **Darkbloom Text Node OS** for the
   installed ID.
4. Repeat section 5 after a fresh serving lease appears. Write to a new output
   path such as `"$MAC_PRIVATE/dual-boot-response.txt"`. Record the verified
   receipt and confirm the return timer boots AMD Linux.

The picker should load the same shim → UKI chain as the earlier one-time boot.
If the picker does not expose the entry or the coordinator rejects its boot
measurements, record that result and keep the working one-time demo. Verify the
chain against a fresh capture before approving another release.

To restore the original firmware order or before installing a replacement boot
image, run `sudo /usr/local/sbin/darkbloom-text-e2e-control disable-dual-boot`
in AMD Linux. This leaves the installed files available for the protected
one-time boot command.

## 7. Test release withdrawal and optionally clean up

While Darkbloom is still running, move its DSSE approval out of the Mac's
active release directory and restart the coordinator. If Darkbloom has already
returned to AMD Linux, boot it again after withdrawing the approval. Observe a
new authenticated capture from the running appliance with
`release_admitted=false` before checking that no new job is routed.

```bash
mkdir -m 0700 -p .halo-e2e/withdrawn
mv .halo-e2e/releases/text-reviewed.dsse.json .halo-e2e/withdrawn/
# Terminal A: stop and restart the mock coordinator again.
python3 poc-rs/scripts/halo-text.py coord --capture
```

In a second terminal, confirm that no provider has a new serving lease and
that a text submission is refused:

```bash
python3 poc-rs/scripts/halo-text.py client -- providers
PRIVATE_SYNTHETIC_PROMPT="$MAC_PRIVATE/withdrawal-prompt.txt"
PRIVATE_NEW_REJECTED_OUTPUT="$MAC_PRIVATE/withdrawal-output.txt"
printf 'withdrawal check\n' >"$PRIVATE_SYNTHETIC_PROMPT"
python3 poc-rs/scripts/halo-text.py client -- text \
  -prompt-file "$PRIVATE_SYNTHETIC_PROMPT" -max-tokens 4 \
  -out "$PRIVATE_NEW_REJECTED_OUTPUT"
```

The final `text` command must fail with no leased provider and must not
create an output file. To keep the demo available, restore the reviewed
approval and restart the mock coordinator when you next want to serve. To
retire the lab setup, run these commands in AMD Linux. Cleanup restores the
original firmware order and revokes the lab sudo grant. It retains ordinary
SSH access and the installed files and firmware record. Preserve only
redacted, reviewed evidence for sharing.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control status
sudo /usr/local/sbin/darkbloom-text-e2e-control cleanup
```
