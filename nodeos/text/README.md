# Build the text inference image

Run these steps from the repository root as the ordinary Linux user on the Halo.
They create verified root/model images and an unsigned UKI. Installation and a
one-time boot use the separate [reviewed root helper](../../tools/halo-e2e/README.md).
See the [main runbook](../../README.md) for coordinator, release and client setup.

Required inputs:

- The vendor x86-64 kernel and its signed modules, AMD llama/HIP packages and
  AMD microcode package. The systemd patch requires `257.13-1~deb13u1`.
- Rootless Podman, Python 3, OpenSSL, curl and space for the selected model,
  root images and staging copies.
- A generated per-device `device.json`, private Wi-Fi and pairing-token files,
  the coordinator CA, a Linux `dbnode`, and the selected GGUF.
- Image storage on the configured Btrfs filesystem's top-level subvolume
  (`subvolid=5`), visible at `/var/lib/darkbloom-text-nodeos` in both OSes.
  The kernel must expose the configured partition's PARTUUID in sysfs uevents.

Generate the device configuration with the root-helper tooling. No disk,
certificate or hostname defaults are supplied. The builder snapshots and checks
that configuration; the initrd matches only its signed partition pin and rejects
ambiguous matches. Keep private inputs outside Git. The default `embedded` Wi-Fi
mode copies the credential into the private image; no signing private key belongs
on the Halo. The opt-in mode below omits the Wi-Fi profile from that image.

```bash
export DEVICE_CONFIG=/ABSOLUTE/DEVICE/inputs/device.json
export AGENT=/ABSOLUTE/LINUX/BIN/dbnode
export COORDINATOR="wss://${COORDINATOR_IP:?set the coordinator LAN IP}:8790/v1/provider/ws"
export CA_CERT=/ABSOLUTE/PRIVATE/coordinator-ca.pem
export WIFI_PROFILE=/ABSOLUTE/PRIVATE/nodeos.nmconnection
export PAIRING_TOKEN_FILE=/ABSOLUTE/PRIVATE/pairing-token
export TEXT_MODEL=/ABSOLUTE/MODELS/model.gguf
export TEXT_MODEL_ID=qwen3-coder-30b-a3b-instruct-q4-k-m
export RETURN_AFTER=25min

bash nodeos/text/scripts/build-patched-systemd-core.sh /ABSOLUTE/PRIVATE/systemd-build
bash nodeos/text/scripts/test-patched-systemd-core.sh /ABSOLUTE/PRIVATE/systemd-build/artifacts/libsystemd-core-257.so
export SYSTEMD_CORE=/ABSOLUTE/PRIVATE/systemd-build/artifacts/libsystemd-core-257.so
# The adjacent systemd-executor and both .sha256 files are required.
bash nodeos/text/build.sh prepare
bash nodeos/text/build.sh rootfs
bash nodeos/text/build.sh models
bash nodeos/text/build.sh initrd
ID=text-repro-001 bash nodeos/text/build.sh options
bash nodeos/text/build.sh uki
```

Outputs are under ignored `nodeos/text/.work/out/`. `NODEOS_TEXT_WORK` may select
another private absolute directory. `TEXT_MODEL_SHA256`, if supplied, must match
the complete model; the builder always hashes it. `RETURN_AFTER` accepts 5..120
minutes. The canonical workflow uses greedy generation without prompt caching,
and the generated-token limit is 1..1024.

On the trusted signing workstation, sign the transferred `unsigned.efi` with
your enrolled certificate and matching unlocked key:

```bash
bash poc-rs/scripts/sign-text-uki.sh \
  --unsigned /ABSOLUTE/TRANSFER/unsigned.efi \
  --out /ABSOLUTE/NEW/SIGNED-DIRECTORY \
  --cert /ABSOLUTE/SIGNER/boot-cert.pem \
  --key /ABSOLUTE/SIGNER/boot-signing.key \
  --cert-sha256 "$ENROLLED_CERT_DER_SHA256"
```

The signer needs Docker, OpenSSL and its pinned base image cached. It produces
`signed.efi`, `signed.efi.sha256` and `signer-environment.txt`. Return the first
two to `out/`, then follow the root-helper runbook to stage the eight literal
files, sign their increasing-sequence manifest, install and boot once. Never
execute the writable build checkout through sudo.

## Opt-in TPM-sealed Wi-Fi

This variant is source support pending a new image build and physical boot test.
Before `prepare`, set `WIFI_MODE=tpm-sealed` and unset `WIFI_PROFILE`. The builder
rejects a plaintext profile in this mode, adds `tpm2-tools` and
`python3-cryptography`, and installs the reviewed decryptor code. Its root image
contains no Wi-Fi profile or PSK. The default demo remains `WIFI_MODE=embedded`.

For Wi-Fi-only calibration, build with `RETURN_AFTER=5min`. The trusted
provisioning flow prepares a public challenge on the pinned EFI partition before
booting the credential-free image. After verifying that boot's TPM proof and
release, it can seal a profile against its exact SHA-256 PCR values **4, 7, 9, 11,
12 and 14**.
It places only ciphertext, root-owned and mode `0600`, at
`/var/lib/darkbloom-text-nodeos/<ID>/wifi-sealed.json` on the main partition.
Use the [sealed Wi-Fi tooling](../../tools/halo-e2e/README.md); do not substitute
an owner-writable program executed through sudo.

Before NetworkManager starts, a fixed root service derives `<ID>` from the signed
`nodeos.root` boot argument. It reads the ciphertext through the existing
read-only host mount after root/model verity verification. Only the matching TPM
boot can recover the profile, which is written mode `0600` into the RAM directory
`/run/NetworkManager/system-connections/darkbloom-wifi.nmconnection`. TPM temporary
objects also stay under `/run`. Status reports only a public availability boolean.

An absent ciphertext blocks NetworkManager and every inference unit. A separate
fixed service may export the requested public TPM quote and event log, then the
independent return timer reboots to factory Linux. The request is only
`/EFI/darkbloom-text/<ID>/calibration/nonce`, exactly 64 lowercase hex characters
and a newline; the signed UKI also pins the ESP's PARTUUID. The service mounts
that partition privately read-only, refuses unexpected directory entries or
symlinks, collects at most 256 KiB in memory, then briefly remounts it to publish
`evidence.json` by an exclusive temporary file and atomic rename. It never writes
the host Btrfs partition, enables networking or starts inference during capture.

A present malformed, symlinked or unsealable ciphertext also blocks networking
and inference, without attempting calibration or an embedded Wi-Fi fallback.
Each changed measured boot, including a
new UKI or changed firmware/Secure Boot/MOK profile, needs a newly reviewed PCR
reference and a new sealed object. This exact-PCR variant uses no signed-policy
or recovery branch. It does not protect credentials from a compromised serving
kernel.

Run the unprivileged runtime fixtures with:

```bash
python3 -B -m unittest discover -s nodeos/text/tests -v
```

The image retains verified storage, confidentiality lockdown, a locked owner
interface, process recycling and engine network confinement. Follow the main
runbook for the encrypted demo's TPM and signed-release admission checks.
Btrfs metadata is still parsed before verity, and the design does not provide
SEV-SNP, a GPU TEE or protection from a compromised serving kernel. Hardware
acceptance remains separate from source/build checks.
