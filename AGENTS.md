# Reproduce the Halo demo

Follow [RUNBOOK.md](RUNBOOK.md) in order. Run each command on the labelled
machine and use the same repository revision on both. Read linked reference
pages when the runbook calls for them.

Read boot, disk and network identifiers from the target Halo. Keep keys,
Wi-Fi credentials, tokens, prompts and TPM captures out of Git and chat.
MOK enrollment and firmware selection happen at the Halo console. Use the
runbook's reviewed root bootstrap and fixed boot commands for privileged
steps.

The demo is complete when AMD Linux is still the default, Darkbloom boots from
the firmware picker, and the mock coordinator path returns an independently
verified receipt for a synthetic text prompt. Record which checkpoints you
observed on hardware.
