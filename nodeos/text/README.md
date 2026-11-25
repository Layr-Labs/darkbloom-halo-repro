# Build the text inference image

Run these steps from the repository root as the ordinary Linux user on the Halo.
They create verified root/model images and an unsigned UKI. Installation and a
one-time boot use the separate [reviewed root helper](../../tools/halo-e2e/README.md).
Follow the [main runbook](../../RUNBOOK.md) for the complete build, signing,
and inference sequence.

Required inputs:

- The vendor x86-64 kernel and its signed modules, AMD llama/HIP packages and
  AMD microcode package. The systemd patch requires `257.13-1~deb13u1`.
- Rootless Podman, Python 3, OpenSSL, curl and space for the selected model,
  root images and staging copies.
- A generated per-device `device.json`, a private pairing-token file, the
  coordinator CA, a Linux `dbnode`, and the selected GGUF. The direct shim
  build also takes a private Wi-Fi keyfile.
- Image storage on the configured Btrfs filesystem's top-level subvolume
  (`subvolid=5`), visible at `/var/lib/darkbloom-text-nodeos` in both OSes.
  The kernel must expose the configured partition's PARTUUID in sysfs uevents.

Build with the commands in [runbook step 2](../../RUNBOOK.md#2-start-the-mac-side-mock-coordinator-and-build-the-image).
The systemd patch requires the matched core library and adjacent executor,
with their checksum files. The builder verifies the device configuration and
pins the partition in the signed boot arguments. Both build modes include the
test provider pairing token. Keep build inputs and images in private storage.

- `WIFI_MODE=tpm-sealed` omits the Wi-Fi profile from the image. Use the
  [wizard test](../../tools/halo-e2e/WIZARD-TEST.md) to calibrate the measured
  boot and seal a copy of the Halo's saved profile on the device. The serving
  boot recovers the profile into a root-only RAM directory.
- `WIFI_MODE=embedded` includes the lab profile specified by `WIFI_PROFILE`
  and uses the direct shim path. This remains the builder's default.

The runbook sets `NODEOS_TEXT_WORK` to a private absolute directory. Read
outputs in its `out/` subdirectory. The default is ignored
`nodeos/text/.work/out/`. The builder hashes the entire model.
If supplied, `TEXT_MODEL_SHA256` must match. `RETURN_AFTER` accepts 5–120 minutes
and defaults to 25 minutes. The text workflow uses greedy generation without
prompt caching and accepts a generated-token limit of 1–1024.

Use [runbook step 3](../../RUNBOOK.md#3-sign-install-and-take-a-calibration-capture)
to sign and install. The signer produces `signed.efi`, `signed.efi.sha256` and
`signer-environment.txt`. Transfer the signed EFI image and its checksum
to the Halo. Keep the private key on the signer.
