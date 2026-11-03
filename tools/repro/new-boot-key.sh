#!/bin/bash
# Generate a fresh public boot certificate and private key on the signing Mac.
set -euo pipefail
umask 077
[[ $# == 2 && $1 == --out ]] || { echo 'usage: new-boot-key.sh --out NEW_PRIVATE_DIRECTORY' >&2; exit 1; }
out=$2
[[ ! -e $out && ! -L $out ]] || { echo 'Output already exists; refusing to overwrite keys' >&2; exit 1; }
mkdir -m 0700 "$out"
out=$(cd "$out" && pwd -P)
cat > "$out/openssl.cnf" <<'CONFIG'
[req]
prompt = no
distinguished_name = dn
x509_extensions = boot
[dn]
CN = Darkbloom Halo reproduction boot signer
[boot]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
CONFIG
openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -config "$out/openssl.cnf" -keyout "$out/boot-signing.key" -out "$out/boot-cert.pem"
openssl x509 -in "$out/boot-cert.pem" -outform DER -out "$out/boot-cert.der"
openssl dgst -sha256 "$out/boot-cert.der" | awk '{print tolower($NF)}' > "$out/boot-cert.sha256"
chmod 0600 "$out/boot-signing.key"
printf 'Generated a new signer in %s\nDER SHA-256: ' "$out"
cat "$out/boot-cert.sha256"
printf 'Keep boot-signing.key on this signing machine. Transfer only the public DER certificate for physical MOK enrollment.\n'
