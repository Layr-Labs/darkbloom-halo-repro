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
- A generated per-device `device.json`, private Wi-Fi and pairing-token files,
  the coordinator CA, a Linux `dbnode`, and the selected GGUF.
- Image storage on the configured Btrfs filesystem's top-level subvolume
  (`subvolid=5`), visible at `/var/lib/darkbloom-text-nodeos` in both OSes.
  The kernel must expose the configured partition's PARTUUID in sysfs uevents.

Build with the commands in [runbook step 2](../../RUNBOOK.md#2-start-the-mac-side-mock-coordinator-and-build-the-image).
The systemd patch requires the matched core library and adjacent executor,
with their checksum files. The builder verifies the device configuration and
pins the partition in the signed boot arguments. Keep inputs and image output
private because the reference image includes its lab Wi-Fi keyfile and
provider pairing token.

Outputs are under ignored `nodeos/text/.work/out/`. Set `NODEOS_TEXT_WORK` to
use another private absolute directory. The builder hashes the entire model.
If supplied, `TEXT_MODEL_SHA256` must match. `RETURN_AFTER` accepts 5–120 minutes
and defaults to 25 minutes. The text workflow uses greedy generation without
prompt caching and accepts a generated-token limit of 1–1024.

Use [runbook step 3](../../RUNBOOK.md#3-sign-install-and-take-a-calibration-capture)
to sign and install. The signer produces `signed.efi`, `signed.efi.sha256` and
`signer-environment.txt`. Transfer the signed EFI image and its checksum
to the Halo. Keep the private key on the signer.
