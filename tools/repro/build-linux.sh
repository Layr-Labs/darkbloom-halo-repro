#!/bin/bash
# Rootless Linux build using the same pinned Rust/musl image as the lab.
set -euo pipefail
umask 077
[[ $# == 2 && $1 == --work ]] || { echo 'usage: build-linux.sh --work ABSOLUTE_PRIVATE_BUILD_DIRECTORY' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $(id -u) != 0 ]] || { echo 'Run as an ordinary user on x86_64 Linux with rootless Podman' >&2; exit 1; }
work=$2
[[ $work == /* && $work != / && $work != *:* && $work != *,* && ! -L $work ]] || { echo 'Invalid build directory' >&2; exit 1; }
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
[[ $ROOT != *:* && $ROOT != *,* ]] || { echo 'Source path contains unsupported bind-mount characters' >&2; exit 1; }
mkdir -p "$work/registry" "$work/git" "$work/target"
chmod 0700 "$work"
work=$(cd "$work" && pwd -P)
image=rust:1.96-alpine@sha256:f5c84c3751de59f0f318acfbed8b2d04693a12d9171f15835d9c11c9ddcf52db
mounts=(-v "$ROOT/poc-rs:/src:ro" -v "$work/registry:/usr/local/cargo/registry" \
        -v "$work/git:/usr/local/cargo/git" -v "$work/target:/target" \
        -w /src -e CARGO_TARGET_DIR=/target)
podman pull "$image"
# Dependency acquisition has network access; the compilation step has none.
podman run --rm "${mounts[@]}" "$image" cargo fetch --locked
podman run --rm --network=none "${mounts[@]}" "$image" \
    cargo build --locked --offline --release -j4 -p db-cli --bin dbnode --bin dbrelease
sha256sum "$work/target/release/dbnode" "$work/target/release/dbrelease" > "$work/linux-binaries.sha256"
printf 'Linux musl binaries and SHA-256 record ready under %s\n' "$work"
