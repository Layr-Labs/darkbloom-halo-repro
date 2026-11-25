# Reproduce the Halo demo

Follow [RUNBOOK.md](RUNBOOK.md) in order. Run each command on the labelled
machine and use the same repository revision on both. Read linked reference
pages when the runbook calls for them.

Read boot, disk and network identifiers from the target Halo. Keep keys,
Wi-Fi credentials, tokens, prompts and TPM captures out of Git and chat.
MOK enrollment and desktop wizard acceptance happen at the Halo console. Use the
runbook's reviewed root bootstrap and fixed boot commands for privileged
steps.

The demo is complete when the chosen boot path starts Darkbloom, the mock
coordinator test returns an independently verified receipt for a synthetic
text prompt, and AMD Linux remains the default. Record the path and
checkpoints you observed on hardware.
