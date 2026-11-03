# Run the attested encrypted text demo

Run the commands labelled **Mac** on the trusted coordinator/signing machine and
those labelled **Halo** in its normal Linux OS as the ordinary owner account.
Use a fresh copy of this repository at the same commit on both machines.
Start with the [prerequisites](README.md#requirements).

This reproduces the functional demo: a signed appliance boots on the Halo,
the Mac verifies fresh AMD TPM evidence against an approved image, and the
client sends an encrypted text request and verifies its encrypted result and receipt.
Use synthetic prompts. The serving kernel remains trusted; this is not a CPU/GPU TEE.
Boot-health diagnostics are not an admission requirement for this functional demo.
The generalized setup and fresh-key path still need validation on your hardware;
local source tests are not a substitute for completing this run.

Commands below use placeholders. Keep the actual device UUIDs, LAN address,
EK material, Wi-Fi keyfile, pairing/API tokens, captured event logs, keys,
prompts, and outputs outside this repository. `nodeos/text/README.md` and the
linked tools define the current accepted input formats. Run every rootless
build command as the ordinary Halo user, and use the fixed root controller
only for the listed install/boot/cleanup operations.

Use private paths such as these from the respective checkout roots; carry
the actual values between machines through a private transfer, not through
Git:

```bash
# Mac, from this repository root:
export HALO_SSH="OWNER@HALO_ADDRESS"
export MAC_LAN_IPV4="MAC_LAN_ADDRESS"
export NEW_INSTALL_ID=text-demo-001
export MAC_PRIVATE="$PWD/.halo-e2e/repro-state"
export PRIVATE_BOOTSTRAP_STAGE="$MAC_PRIVATE/bootstrap"
mkdir -p "$PRIVATE_BOOTSTRAP_STAGE"
chmod 0700 "$MAC_PRIVATE" "$PRIVATE_BOOTSTRAP_STAGE"

```

```bash
# Halo, from this repository root as its ordinary user:
export MAC_LAN_IPV4="SAME_MAC_LAN_ADDRESS"
export NEW_INSTALL_ID=text-demo-001
export NEXT_SEQUENCE=1
export VERSION=0.1.0-demo
export SVN=1
export OWNER_USER=$(id -un)
export PRIVATE_HALO_STAGE="$HOME/darkbloom-text-repro"
export PRIVATE_HALO_MODEL="$PRIVATE_HALO_STAGE/model"
export HALO_STAGING="/home/$OWNER_USER/darkbloom-text-e2e-staging"
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
from its shim boot entry; and `WIFI_IFACE` for the connected wireless device.
The factory EFI directory must contain `shimx64.efi` and `mmx64.efi`.


On a fresh machine, generate a new Secure Boot signing key **off the Halo**:

```bash
bash tools/repro/new-boot-key.sh --out "$MAC_PRIVATE/new-boot-key"
export ENROLLED_CERT_DER="$MAC_PRIVATE/new-boot-key/boot-cert.der"
export ENROLLED_CERT_PEM="$MAC_PRIVATE/new-boot-key/boot-cert.pem"
export MAC_ONLY_BOOT_KEY="$MAC_PRIVATE/new-boot-key/boot-signing.key"
```

On the Halo, transfer **only** that public DER certificate and enroll it:

```bash
PUBLIC_BOOT_CERT_DER="$HOME/boot-cert.der"  # transfer only the public DER here
sudo mokutil --import "$PUBLIC_BOOT_CERT_DER"
# Reboot and physically confirm enrollment through shim/MokManager.
```

Enroll only its public certificate through shim/MokManager with physical
confirmation, then verify Secure Boot and the enrolled certificate from the
normal OS. Do not transfer the private key to the Halo. The operator must review and
pin the certificate's DER SHA-256 in the signer and root bootstrap before
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
`boot`, and `cleanup`.

## 2. Start the Mac-side mock coordinator and build the image

Transfer these files privately as the steps below produce them. Set each path
variable on the machine where it is used; the two shells do not share variables.
Never transfer the boot or release signing private keys to the Halo.

| Direction | Files / destination |
| --- | --- |
| Mac → Halo | `inputs/device.json` → `$PRIVATE_HALO_STAGE/device.json`; bootstrap archive → owner's home |
| Mac → Halo | `.halo-e2e/tls/ca.pem` → `$PRIVATE_HALO_STAGE/ca.pem`; `.halo-e2e/provider-token` → `$PRIVATE_HALO_STAGE/pairing-token` |
| Halo → Mac | `.work/out/unsigned.efi` → `$UNSIGNED_EFI`; factory `shimx64.efi` → `$REVIEWED_FACTORY_SHIM` |
| Mac → Halo | Signed EFI and SHA-256 file → `$SIGNED_EFI` and `$SIGNED_EFI_SHA256` |
| Halo → Mac → Halo | Bundle `manifest.json` → `$MAC_PRIVATE/manifest.json`; signed `manifest.sig` → `$HALO_STAGING/manifest.sig` |
| Halo → Mac | Runtime template → `$MAC_PRIVATE/runtime-template.json` |

Keep credential files mode `0600` and staging directories `0700`.


Build the current Rust binaries from a frozen source revision and record
their SHA-256. The Mac runner stores credentials and captures in ignored
`.halo-e2e/` with private permissions. It creates a TLS 1.3 certificate for
both localhost and the Mac's LAN IP; local clients pin its CA. The Halo
connects directly over LAN WSS with the same pinned CA.

```bash
cargo build --manifest-path poc-rs/Cargo.toml --locked -p db-cli --bins
python3 poc-rs/scripts/halo-text.py init --lan-ip "$MAC_LAN_IPV4"
python3 poc-rs/scripts/halo-text.py coord --capture
```

On the Halo, build fresh compatible `dbnode` and `dbrelease` binaries from
the same frozen source using the rootless pinned Rust/Alpine image. The
[`build-linux.sh`](tools/repro/build-linux.sh) wrapper fetches locked
dependencies into a private ordinary-user cache, then builds offline with
container networking disabled. It emits SHA-256 records for both outputs.
Copy the Mac TLS CA to the Halo's
private staging area, and prepare
a private provider pairing-token file containing the token from
`.halo-e2e/provider-token`. The fixed root helper's `wifi-profile` operation
can write the active profile **directly** to a private mode-0600 file; never
print that operation's output. Prepare one approved GGUF model and the fixed
`nodeos/text/workflow.json`.

```bash
# Halo ordinary user, after the fixed root bootstrap has been installed:
umask 077
install -d -m 0700 "$PRIVATE_HALO_STAGE"
sudo /usr/local/sbin/darkbloom-text-e2e-control wifi-profile \
  >"$PRIVATE_HALO_STAGE/nodeos.nmconnection"
chmod 0600 "$PRIVATE_HALO_STAGE/nodeos.nmconnection"
```

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
export WIFI_PROFILE="$PRIVATE_HALO_STAGE/nodeos.nmconnection"
export PAIRING_TOKEN_FILE="$PRIVATE_HALO_STAGE/pairing-token"
export TEXT_MODEL="$PRIVATE_HALO_MODEL/model.gguf"
export TEXT_MODEL_ID=qwen3-coder-30b-a3b-instruct-q4-k-m
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
package versions; do not transplant a prior image. Review `.work/out/options`, the root and
model hashes, image contents, `build-inputs.json`, and the unsigned UKI
sections before signing. The initrd checker must find the signed SHA-384
module and narrow early loader. Debug, external journal export, and free-form
agent arguments are rejected by the text profile.

## 3. Sign, install, and take a calibration capture

Transfer only `.work/out/unsigned.efi` to the Mac signer. Sign with the
enrolled private key in its isolated, pinned signer environment, verify the
signature against the pinned public certificate, and return `signed.efi`
plus `signed.efi.sha256` to the Halo staging `out/`. The signer refuses an
already-signed, multi-profile or unexpected UKI. The private key never goes
to the Halo.

```bash
# Mac only: the private boot key is mounted read-only into the signer container.
ENROLLED_CERT_DER_SHA256=$(cat "$MAC_PRIVATE/new-boot-key/boot-cert.sha256")
NEW_PRIVATE_SIGN_DIR="$MAC_PRIVATE/signed-$NEW_INSTALL_ID"
docker pull 'debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4'
bash poc-rs/scripts/sign-text-uki.sh --unsigned "$UNSIGNED_EFI" \
  --out "$NEW_PRIVATE_SIGN_DIR" --cert "$ENROLLED_CERT_PEM" \
  --key "$MAC_ONLY_BOOT_KEY" --cert-sha256 "$ENROLLED_CERT_DER_SHA256"
```

On the Halo, after uploading `signed.efi` and its hash record to private
paths, stage exactly the eight data files. This example uses the builder's
default private work directory; substitute `NODEOS_TEXT_WORK/out` if set:

```bash
install -d -m 0700 "$HALO_STAGING/out"
cp --reflink=auto nodeos/text/.work/out/{root.erofs,root.verity,models.erofs,models.verity,payload.sha256,install-id} \
  "$HALO_STAGING/out/"
install -m 0600 "$SIGNED_EFI" "$HALO_STAGING/out/signed.efi"
install -m 0600 "$SIGNED_EFI_SHA256" "$HALO_STAGING/out/signed.efi.sha256"
python3 tools/halo-e2e/make-bundle.py --sequence "$NEXT_SEQUENCE" "$HALO_STAGING"
```

Transfer only `manifest.json` to the Mac, sign it there, and return
`manifest.sig` to the fixed Halo staging directory:

```bash
openssl dgst -sha256 -sign "$MAC_ONLY_BOOT_KEY" \
  -out "$MAC_PRIVATE/manifest.sig" "$MAC_PRIVATE/manifest.json"
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
PRIVATE_REFERENCE_EVENTLOG="$MAC_PRIVATE/reference-eventlog.bin"
python3 poc-rs/scripts/halo-text.py extract-capture "$PRIVATE_CAPTURE_JSON" \
  --out "$PRIVATE_REFERENCE_EVENTLOG"
poc-rs/target/debug/dbrelease inspect-log -in "$PRIVATE_REFERENCE_EVENTLOG"

```

To avoid copying a large GGUF to the Mac, make one **dev UKI manifest
template** on the Halo from the already-hashed model and exact `dbnode`,
then review it on the Mac. Its placeholder PCR 9 is not trusted for
production; `-runtime-from` imports only the pinned runtime fields. It
cannot be combined with `-agent`, `-engine`, `-models-dir`, `-hash-cache`, or
the `-text-*` flags in the production build.
Set `REVIEWED_MIN_SCRTM` from the target's measured S-CRTM event, not the
displayed BIOS version. For the reference RAH-002 configuration this value is `MFGB0.04.00`; check your own measured value. Supply this flag in both
manifests and review it against the reference log.

```bash
# Halo ordinary user, using the freshly built Linux dbrelease binary:
ZERO64=$(printf '%064d' 0)  # dev template only; never a production PCR 9
PRIVATE_RUNTIME_TEMPLATE="$PRIVATE_HALO_STAGE/runtime-template.json"
"$HALO_DBRELEASE" build -channel dev -version "$VERSION" -svn "$SVN" \
  -min-bios "$REVIEWED_MIN_SCRTM" \
  -shim "$FACTORY_SHIM" -uki "$SIGNED_EFI" -pcr9 "$ZERO64" \
  -agent "$AGENT" -text-model-id "$TEXT_MODEL_ID" \
  -text-model "$TEXT_MODEL" -text-workflow nodeos/text/workflow.json \
  -out "$PRIVATE_RUNTIME_TEMPLATE"

```

```bash
# Mac signer, after transferring and reviewing the dev template:
export VERSION=0.1.0-demo
export SVN=1
PRIVATE_RUNTIME_TEMPLATE="$MAC_PRIVATE/runtime-template.json"
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

## 5. Independent client check and cleanup

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
  -prompt-file "$PRIVATE_PROMPT_FILE" -max-tokens 64 -out "$PRIVATE_NEW_OUTPUT"
```

Success: the command exits zero, prints `receipt verified`, and creates the
response text file with mode `0600`. Read it locally; the coordinator routes the
sealed request and result. An unknown release or failed fresh proof must not receive a lease.

After the one-shot return, withdraw the demo release: move its DSSE file out of
`.halo-e2e/releases/`, restart the mock coordinator, and confirm that a new
text request is refused with no leased worker. Withdrawal is a coordinator
policy change; it does not alter an already completed client result.

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
create an output file. Verify the factory boot order and invoke the fixed
controller's `cleanup` to revoke its sudo grant. It intentionally retains
ordinary SSH authorization and installed data/boot entries; inspect and
remove those separately under the owner's change process. Preserve only
redacted, reviewed evidence for sharing. Do not publish captures, event-log
contents, certificates unique to the chip, private prompts, or secrets.

```bash
sudo /usr/local/sbin/darkbloom-text-e2e-control status
sudo /usr/local/sbin/darkbloom-text-e2e-control cleanup
```
