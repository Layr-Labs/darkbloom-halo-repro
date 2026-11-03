# Rust components for the Halo text demo

Follow the repository [runbook](../RUNBOOK.md) for the hardware workflow. It
covers fresh keys, a reviewed Node OS image, physical MOK enrollment, TPM
calibration and release approval, and one encrypted text request. This folder
contains the mock coordinator, provider agent, consumer, release tool, and
focused test fixtures used by that workflow.

## Binaries

`cargo build --locked -p db-cli --bins` builds:

| Binary | Role |
| --- | --- |
| `dbcoord` | TLS coordinator, TPM challenge/admission and worker lease |
| `dbnode` | Sealed Node OS provider agent and local Llama engine client |
| `dbclient` | Consumer-side attestation, TPM-bound text sealing, result and receipt verification |
| `dbrelease` | Release signing, verification and boot measurement tooling |

[`scripts/halo-text.py`](scripts/halo-text.py) runs the Mac-side private state,
coordinator and consumer for the demo. [`scripts/sign-text-uki.sh`](scripts/sign-text-uki.sh)
signs the measured UKI on the workstation with a separately enrolled boot key.
The signer key, TLS and release keys, pairing token, Wi-Fi profile, model
weights, event logs and generated images belong in ignored private directories.

## Local source checks

From the repository root, run `bash tools/repro/check.sh`. For focused Rust
checks from this directory:

```bash
cargo check --locked -p db-cli --bins
cargo test --locked -p db-engine --test llama
cargo test --locked -p db-coord --test http
cargo test --locked -p db-cli --test runtime_from
```

The `db-testenv` and `db-e2e` crates use a local software TPM for development
tests; their results do not authenticate a physical Halo. The hardware path
requires the fresh TPM quote, enrolled boot certificate, measured UKI and
approved release described in the runbook.

## Source layout

- `crates/tpm2`, `crates/tpmdev`, `crates/tpmattest`: TPM transport, device
  commands, quote and key binding, EK-chain and release verification.
- `crates/release`, `crates/gojson`: signed release policy, boot measurements
  and canonical JSON encoding.
- `crates/wire`, `crates/sealbox`, `crates/tls`: protocol, end-to-end sealing
  and TLS.
- `crates/engine`, `crates/node`: local Llama inference adapter and provider
  agent.
- `crates/coord`, `crates/client`, `crates/cli`: coordinator, consumer and
  command-line entrypoints.

The text request requires consumer-side production-tier attestation and a
TPM-bound job key. The coordinator and sealed Node OS remain trusted at
runtime; boot attestation alone does not protect live plaintext after a
privileged compromise of the serving OS.
