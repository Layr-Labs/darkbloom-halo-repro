# Halo setup wizard hardware test

This is the preview desktop wizard path. Use the [fresh Halo guide](../../RUNBOOK.md)
for the fixed-model mock inference demo. Before preparing the preview menu,
restore the original firmware order with the protected `disable-dual-boot`
operation if the firmware boot picker was enabled.

Use a separate image and test account with the mock coordinator. The wizard
reuses the active factory NetworkManager WPA-PSK or WPA3-SAE system profile.
Factory Linux already has that credential. The test covers protection of
Darkbloom's saved copy after provisioning.

1. Build a reviewed `WIFI_MODE=tpm-sealed` Node OS image. Use a test pairing
   token scoped to the mock coordinator, and leave `WIFI_PROFILE` unset.
   Sign the UKI with the enrolled test signer and install the signed data
   bundle through the existing protected text installer.
2. Install the fixed wizard helper and GNOME launcher from a reviewed,
   hash-verified source archive. Factory Linux needs `tpm2-tools`, Zenity and
   Python's cryptography package. In a fresh root-owned directory, use
   [the archive installer](install-wizard-archive.py) to verify the exact
   archive before executing [bootstrap](wizard-bootstrap.sh). Bootstrap
   adds sudo access for the fixed wizard commands only.
3. Run the helper's `prepare-menu` operation. Check via `bootctl list` that the
   factory AMD entry stays default and that Darkbloom appears as a second entry.
   The helper references the existing signed UKI on the EFI partition.
4. With the Halo in factory Linux, capture the output of the helper's
   `calibration-key` operation as `pinned-ak.json` on the signing Mac. Generate
   a fresh 32-byte nonce on the Mac and stage it as `calibration-nonce` in
   `~/darkbloom-halo-setup` (64 lowercase hex characters followed by a newline).
   Run `calibrate`. This boots through the same menu entry the wizard will use.
   No Wi-Fi credential is installed at this point. The signed image writes a
   bounded TPM quote and event log to its dedicated EFI directory while
   networking and inference are disabled, then returns to factory Linux on
   the configured timer. Collect the file through the helper's
   `calibration-report` operation after SSH returns.
5. Review the exact EFI chain and event log. Build the release manifest with
   `dbrelease build -uki-menu -sdboot <factory-systemd-boot.efi>`, the correct
   shim, signed UKI, existing model/runtime pins and the observed PCR 9 and
   reference event log. Confirm the predicted and observed boot measurements
   match. Run `dbrelease verify-calibration -in evidence.json -ak-public
   pinned-ak.json -nonce <nonce-hex> -manifest <reviewed-manifest.json>
   -release-id <install-id>` to generate the canonical `expected-pcrs.json`.
   The verifier checks the quote signature from the pinned Halo key, its
   fresh nonce, the event-log replay, and the approved release measurements.
   Sign those exact bytes
   with the enrolled test signer as `expected-pcrs.sig`. Put both files in
   the owner's `~/darkbloom-halo-setup` directory and use `arm` to install
   those reviewed pins and remove the calibration exchange from the EFI partition.
   The signing key stays on the signing workstation.
6. Approve the exact release at the mock coordinator. In factory Linux, open
   **Darkbloom Setup** and select **Finish setup and restart**.
   The helper seals the active profile and checks that the factory boot's PCRs
   differ. It enables a six-second menu and automatically starts Darkbloom
   through the one-time menu selection.
7. Confirm Darkbloom connects over Wi-Fi, the mock coordinator
   grants its attested release a lease, and the test client gets a verified
   receipt for an encrypted synthetic prompt. On the next normal reboot,
   verify both AMD Linux and Darkbloom appear in the visible menu and AMD Linux
   remains the default.

Keep the release, signed credential policy and ciphertext separate from the
image. Changing the measured boot requires new reviewed measurements and
resealing for this prototype. Keep the physical console available for recovery.
