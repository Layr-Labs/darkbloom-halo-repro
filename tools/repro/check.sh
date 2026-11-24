#!/bin/bash
# Source checks only: no sudo, TPM, firmware, enrollment or reboot operations.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$ROOT"
python3 -B -m unittest discover -s tools/halo-e2e
python3 -B -m unittest discover -s tools/repro
while IFS= read -r script; do bash -n "$script"; done < <(find nodeos/text tools/repro tools/halo-e2e -name '*.sh' -type f -print)
bash -n nodeos/initrd/mkinitrd.sh
bash -n poc-rs/scripts/sign-text-uki.sh
cd poc-rs
cargo test --locked -p db-wire -p db-release -p db-tpmattest -p db-engine -p db-coord -p db-node --lib
cargo test --locked -p db-engine --test llama
cargo test --locked -p db-coord --test http
cargo test --locked -p db-cli --test runtime_from
cargo check --locked -p db-cli --bins
printf '\nLocal source checks passed. Physical boot and hardware acceptance remain separate.\n'
