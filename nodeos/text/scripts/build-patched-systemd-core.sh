#!/usr/bin/env bash
# Build the narrow Darkbloom systemd 257.13 core and executor patch in rootless Podman.
# Run on the Halo as its ordinary user, never as host root.
set -euo pipefail
export LC_ALL=C
umask 077

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux x86_64 required' >&2; exit 1; }
[[ $EUID -ne 0 ]] || { echo 'Run as the ordinary Halo user, not root' >&2; exit 1; }
command -v podman >/dev/null
command -v curl >/dev/null
command -v sha256sum >/dev/null
OUT=${1:?usage: build-patched-systemd-core.sh ABSOLUTE_PRIVATE_OUTPUT_DIR}
[[ $OUT == /* && $OUT != / ]] || { echo 'Output must be an absolute private directory' >&2; exit 1; }
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PATCH=$SCRIPT_DIR/../patches/0001-confidentiality-restrict-fs-fail-closed.patch
[[ -f $PATCH ]] || { echo 'Missing pinned patch' >&2; exit 1; }
mkdir -p "$OUT/source" "$OUT/artifacts"
chmod 0700 "$OUT" "$OUT/source" "$OUT/artifacts"
BASE=https://deb.debian.org/debian/pool/main/s/systemd
fetch() {
    local name=$1 expected=$2
    if [[ ! -f $OUT/source/$name ]]; then
        curl --fail --location --silent --show-error --retry 3 \
            --output "$OUT/source/$name" "$BASE/$name"
    fi
    printf '%s  %s\n' "$expected" "$OUT/source/$name" | sha256sum --check --status || {
        echo "Debian source checksum mismatch: $name" >&2; exit 1;
    }
}
fetch 'systemd_257.13-1~deb13u1.dsc' \
    1b3405d671a82d1e20c9d99f52d4336aafe8543b28d04e91b7f1f586d3a667c7
fetch 'systemd_257.13.orig.tar.gz' \
    1eb7d5f9ff8a426ff880a3cded9ce819613ba8003ac5ddde9eca162f14ddabe7
fetch 'systemd_257.13-1~deb13u1.debian.tar.xz' \
    9c6e435d613b996efcdb3b7dd9a4cebaa745333a3f64dc722f3fad646f1fdc1a
sha256sum "$PATCH" >"$OUT/artifacts/patch.sha256"

# The source identity is pinned above. Debian's signed apt repository supplies
# build dependencies inside this disposable container. Record their versions;
# this script does not claim byte-identical output across changing toolchains.
podman run --rm \
    -v "$OUT:/work" -v "$PATCH:/darkbloom.patch:ro" \
    -w /work docker.io/library/debian:trixie /bin/bash -euo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive LC_ALL=C
        cat >/etc/apt/sources.list.d/darkbloom-build.sources <<EOF
Types: deb-src
URIs: http://deb.debian.org/debian
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF
        apt-get update
        apt-get install -y --no-install-recommends dpkg-dev build-essential fakeroot patch ca-certificates
        apt-get build-dep -y systemd
        dpkg-source --no-check -x source/systemd_257.13-1~deb13u1.dsc systemd-257.13
        patch --fuzz=0 -d systemd-257.13 -p1 < /darkbloom.patch
        cd systemd-257.13
        dpkg-checkbuilddeps
        DEB_BUILD_OPTIONS="nocheck nodoc" dpkg-buildpackage -B -uc -us -j"$(nproc)"
        dpkg-deb -x ../libsystemd-shared_257.13-1~deb13u1_amd64.deb ../extracted
        core=../extracted/usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-257.so
        test -s "$core"
        cp "$core" ../artifacts/libsystemd-core-257.so
        sha256sum ../artifacts/libsystemd-core-257.so > ../artifacts/libsystemd-core-257.so.sha256
        dpkg-deb -x ../systemd_257.13-1~deb13u1_amd64.deb ../extracted-systemd
        executor=../extracted-systemd/usr/lib/systemd/systemd-executor
        test -s "$executor"
        cp "$executor" ../artifacts/systemd-executor
        sha256sum ../artifacts/systemd-executor > ../artifacts/systemd-executor.sha256
        dpkg-query -W -f="\${Package} \${Version}\n" \
            gcc clang meson ninja-build libbpf-dev libsystemd-shared 2>/dev/null > ../artifacts/build-toolchain.txt || true
    '
printf 'Patched systemd core: %s\n' "$OUT/artifacts/libsystemd-core-257.so"
cat "$OUT/artifacts/libsystemd-core-257.so.sha256"
printf 'Patched systemd executor: %s\n' "$OUT/artifacts/systemd-executor"
cat "$OUT/artifacts/systemd-executor.sha256"
