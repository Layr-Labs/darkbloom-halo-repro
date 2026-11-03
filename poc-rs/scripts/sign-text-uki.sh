#!/bin/bash
# Sign one text UKI on the trusted signing workstation with its enrolled MOK.
# Usage: --unsigned FILE --out NEW_DIR --cert PEM --key KEY --cert-sha256 HEX
# Only signed.efi, signed.efi.sha256 and signer-environment.txt leave the container.
set -euo pipefail
umask 077

image=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
cert_pin=

die() { printf 'sign-text-uki: %s\n' "$*" >&2; exit 1; }
normalize_pin() {
    [[ $1 =~ ^[[:xdigit:]]{64}$ ]] || die '--cert-sha256 must be the 64-hex SHA-256 of the DER certificate'
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}
hash_file() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }

if [[ ${1:-} == --container ]]; then
    [[ $# == 3 && $2 == --cert-sha256 ]] || die 'internal container invocation requires an explicit certificate pin'
    cert_pin=$(normalize_pin "$3")
    [[ -r /inputs/unsigned.efi && -r /inputs/boot-cert.pem && -r /inputs/boot-signing.key ]] || die 'signer inputs are not mounted'
    export DEBIAN_FRONTEND=noninteractive
    mkdir -p /tmp/packages /tmp/tools
    apt-get -o Dir::Cache::pkgcache=/tmp/pkgcache.bin \
        -o Dir::Cache::srcpkgcache=/tmp/srcpkgcache.bin \
        update >/tmp/apt-update.log 2>&1 || { cat /tmp/apt-update.log >&2; exit 1; }
    cd /tmp/packages
    apt-get download sbsigntool libssl3t64 openssl openssl-provider-legacy \
        python3-minimal python3.13-minimal python3.13 libpython3.13-minimal \
        libpython3.13-stdlib python3-pefile libexpat1 zlib1g libffi8 \
        libbz2-1.0 liblzma5 libsqlite3-0 libreadline8t64 libncursesw6 \
        libtinfo6 libuuid1 >/tmp/apt-download.log 2>&1 \
        || { cat /tmp/apt-download.log >&2; exit 1; }
    : >/tmp/tool-versions.txt
    for package in ./*.deb; do
        dpkg-deb -f "$package" Package Version Architecture >>/tmp/tool-versions.txt
        dpkg-deb -x "$package" /tmp/tools
        rm "$package"
    done
    library_dir=$(find /tmp/tools/usr/lib -mindepth 1 -maxdepth 1 -type d -name '*-linux-gnu' -print -quit)
    [[ -n $library_dir ]] || die 'extracted libraries missing'
    export LD_LIBRARY_PATH=$library_dir
    export PATH=/tmp/tools/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
    export PYTHONHOME=/tmp/tools/usr
    export PYTHONPATH=/tmp/tools/usr/lib/python3/dist-packages
    export OPENSSL_CONF=/tmp/tools/etc/ssl/openssl.cnf
    export OPENSSL_MODULES=$library_dir/ossl-modules

    actual_cert=$(openssl x509 -in /inputs/boot-cert.pem -outform DER | sha256sum | cut -d' ' -f1)
    [[ $actual_cert == "$cert_pin" ]] || die 'certificate does not match the supplied DER fingerprint'
    python3 - <<'PY'
import pefile
p = pefile.PE('/inputs/unsigned.efi')
security = p.OPTIONAL_HEADER.DATA_DIRECTORY[4]
if security.Size or security.VirtualAddress:
    raise SystemExit('UKI already has a certificate table')
if p.FILE_HEADER.Machine != 0x8664:
    raise SystemExit('UKI is not x86-64')
names = [s.Name.rstrip(b'\0').decode('ascii') for s in p.sections]
if len(names) != len(set(names)) or not {'.linux', '.cmdline', '.initrd', '.osrel', '.uname', '.sbat'} <= set(names):
    raise SystemExit('UKI lacks required single-profile text boot sections or has duplicates')
if {'.profile', '.dtbauto', '.hwids', '.efifw'} & set(names):
    raise SystemExit('selection-dependent UKI sections are unsupported')
PY
    cd /output
    sbsign --key /inputs/boot-signing.key --cert /inputs/boot-cert.pem \
        --output signed.efi /inputs/unsigned.efi >/tmp/sbsign.log 2>&1 \
        || { cat /tmp/sbsign.log >&2; exit 1; }
    sbverify --cert /inputs/boot-cert.pem signed.efi >/tmp/sbverify.log 2>&1 \
        || { cat /tmp/sbverify.log >&2; exit 1; }
    sha256sum signed.efi >signed.efi.sha256
    {
        printf 'container_image=%s\n' "$image"
        printf 'certificate_der_sha256=%s\n' "$actual_cert"
        printf 'unsigned_efi_sha256=%s\n' "$(sha256sum /inputs/unsigned.efi | cut -d' ' -f1)"
        printf 'signed_efi_sha256=%s\n' "$(cut -d' ' -f1 signed.efi.sha256)"
        printf 'openssl_version=%s\n' "$(openssl version)"
        printf 'sbsign_version=%s\n' "$(sbsign --version 2>&1 | head -1)"
        printf 'sbverify_version=%s\n' "$(sbverify --version 2>&1 | head -1)"
        printf 'extracted_packages:\n'
        cat /tmp/tool-versions.txt
    } >signer-environment.txt
    exit 0
fi

script_dir=$(cd "$(dirname "$0")" && pwd -P)
script=$script_dir/$(basename "$0")
cert= key= unsigned= out=
while (($#)); do
    case "$1" in
        --unsigned|--out|--cert|--key|--cert-sha256)
            (($# >= 2)) || die "$1 needs a path"
            case "$1" in
                --unsigned) unsigned=$2 ;;
                --out) out=$2 ;;
                --cert) cert=$2 ;;
                --key) key=$2 ;;
                --cert-sha256) cert_pin=$2 ;;
            esac
            shift 2 ;;
        *) die 'usage: --unsigned FILE --out NEW_DIR --cert PEM --key KEY --cert-sha256 HEX' ;;
    esac
done
[[ -n $unsigned && -n $out && -n $cert && -n $key && -n $cert_pin ]] || die 'all of --unsigned, --out, --cert, --key and --cert-sha256 are required'
cert_pin=$(normalize_pin "$cert_pin")
for path in "$unsigned" "$cert" "$key" "$script"; do
    [[ -f $path && ! -L $path && -s $path ]] || die "missing, empty or linked input: $path"
    [[ $path != *,* ]] || die 'Docker bind source paths cannot contain commas'
done
unsigned=$(cd "$(dirname "$unsigned")" && pwd -P)/$(basename "$unsigned")
cert=$(cd "$(dirname "$cert")" && pwd -P)/$(basename "$cert")
key=$(cd "$(dirname "$key")" && pwd -P)/$(basename "$key")
out_parent=$(cd "$(dirname "$out")" && pwd -P) || die 'output parent directory is missing'
out=$out_parent/$(basename "$out")
[[ ! -e $out && ! -L $out ]] || die "output already exists: $out"
[[ $out != *,* ]] || die 'Docker bind destination path cannot contain commas'
host_cert=$(openssl x509 -in "$cert" -outform DER | openssl dgst -sha256 | awk '{print $NF}')
[[ $host_cert == "$cert_pin" ]] || die 'certificate does not match the supplied DER fingerprint'
cert_public=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $NF}')
key_public=$(openssl pkey -in "$key" -passin pass: -pubout -outform DER | openssl dgst -sha256 | awk '{print $NF}') || die 'private key must be readable without an interactive password'
[[ $cert_public == "$key_public" ]] || die 'private key does not match the certificate'
docker=$(command -v docker) || die 'Docker CLI is not on PATH'
[[ -x $docker ]] || die 'Docker CLI is not executable'
"$docker" image inspect "$image" >/dev/null || die 'pinned Debian signer image is not cached'
stage=$(mktemp -d "$out_parent/.sign-text-uki.XXXXXXXX")
cleanup() { [[ -z ${stage:-} ]] || rm -rf -- "$stage"; }
trap cleanup EXIT
"$docker" run --rm --read-only \
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m \
    --tmpfs /var/lib/apt/lists:rw,nosuid,nodev,size=80m \
    --mount "type=bind,src=$script,dst=/signer.sh,readonly" \
    --mount "type=bind,src=$unsigned,dst=/inputs/unsigned.efi,readonly" \
    --mount "type=bind,src=$cert,dst=/inputs/boot-cert.pem,readonly" \
    --mount "type=bind,src=$key,dst=/inputs/boot-signing.key,readonly" \
    --mount "type=bind,src=$stage,dst=/output" \
    "$image" /bin/bash /signer.sh --container --cert-sha256 "$cert_pin"
[[ -s $stage/signed.efi && -s $stage/signed.efi.sha256 && -s $stage/signer-environment.txt ]] \
    || die 'signer did not produce all three expected files'
[[ $(find "$stage" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ') == 3 ]] \
    || die 'signer produced unexpected files'
expected=$(awk 'NR==1 {print $1}' "$stage/signed.efi.sha256")
actual=$(hash_file "$stage/signed.efi")
[[ $expected == "$actual" ]] || die 'signed EFI hash file does not match its bytes'
mv -- "$stage" "$out"
stage=
printf 'Signed UKI verified against the supplied certificate: %s\n' "$out/signed.efi"
