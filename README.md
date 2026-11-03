# Run the Darkbloom text demo on AMD Halo

Boot a signed inference appliance on your Halo, verify it from a mock coordinator
on a Mac using AMD Pluton TPM evidence, send an encrypted text prompt to the
Radeon GPU, and decrypt the response with a verified receipt.

**Follow [RUNBOOK.md](RUNBOOK.md)** for device setup, key enrollment, builds,
the two-boot attestation/approval sequence, a text request, and cleanup.

## Requirements

- A Ryzen AI Halo with Pluton TPM, Secure Boot enabled, a monitor and keyboard
  for MOK enrollment, and an ordinary Linux account with initial sudo access.
- The reference software profile: RAH-002 / Ryzen AI Max+ PRO 495 / gfx1151,
  vendor Rex kernel `7.2.7+rex-amd64`, Debian systemd `257.13-1~deb13u1`,
  the vendor RyAI package feeds, and rootless Podman on the Halo.
- The image store on Btrfs top-level subvolume 5. Other disk layouts need an
  installer/initrd adaptation. Configure your own partition identifiers.
- A trusted Mac with Rust 1.96.0, Python 3, OpenSSL and Docker. Keep boot and
  release signing private keys on the Mac.
- Both machines on a reachable LAN. Allow Halo connections to Mac TCP port
  8790 while keeping the firewall enabled.
- Storage for the 18.6 GB model, its verity image, rootfs builds and installation.

This is an attested encrypted inference demo. The serving kernel and GPU stack
remain trusted; the hardware does not provide SEV-SNP or a demonstrated GPU TEE.
Use synthetic prompts. Generate your own keys and collect your own measurements.

To check the source and installation interfaces before using hardware:

```bash
bash tools/repro/check.sh
```
