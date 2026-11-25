#!/bin/bash
# Run from a root-owned, independently hash-verified helper archive.
# The existing Darkbloom text installer must already be installed.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

[[ $(id -u) == 0 && $# == 3 ]]
owner=$1
release=$2
wifi_interface=$3
[[ $owner =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ $release =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]
[[ $wifi_interface =~ ^[a-zA-Z0-9_.-]+$ ]]
[[ $(getent passwd "$owner" | cut -d: -f6) == "/home/$owner" ]]
[[ $(id -u "$owner") != 0 && -d /sys/class/net/$wifi_interface/wireless ]]
if grep -q 'nodeos.root=' /proc/cmdline; then exit 1; fi

source_dir=$(cd "$(dirname -- "$0")" && pwd -P)
lib=/usr/local/libexec/darkbloom-halo-setup
state=/var/lib/darkbloom-halo-setup
helper=/usr/local/sbin/darkbloom-halo-setup
launcher=/usr/local/bin/darkbloom-setup
desktop=/usr/local/share/applications/darkbloom-setup.desktop
grant=/etc/sudoers.d/darkbloom-halo-setup
staging=/home/$owner/darkbloom-halo-setup
for path in "$source_dir" /usr/local/libexec/darkbloom-text-e2e /var/lib/darkbloom-text-e2e; do
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]]
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || exit 1
done
for path in "$lib" "$state" "$helper" "$launcher" "$desktop" "$grant"; do
    [[ ! -e $path && ! -L $path ]] || { echo "Setup destination already exists: $path" >&2; exit 1; }
done
for relative in wizard-admin.py sealed-wifi.py sealed-wifi-seal.py sealed-wifi-check.py collect_quote.py setup.py setup.desktop; do
    path=$source_dir/$relative
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 ]]
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || exit 1
done
for name in tpm2_createprimary tpm2_startauthsession tpm2_policypcr tpm2_pcrread tpm2_create tpm2_load tpm2_unseal tpm2_flushcontext; do
    command -v "$name" >/dev/null || { echo 'Install the distribution tpm2-tools package first.' >&2; exit 1; }
done
python3 -I -c 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM'

install -d -o root -g root -m 0755 /usr/local/share/applications
install -d -o root -g root -m 0700 "$lib" "$state"
committed=0
finish() {
    result=$?
    trap - EXIT
    if [[ $committed == 0 ]]; then
        rm -f -- "$helper" "$launcher" "$desktop" "$grant"
        rm -rf -- "$lib" "$state"
    fi
    exit "$result"
}
trap finish EXIT
install -m 0600 "$source_dir"/{wizard-admin.py,sealed-wifi.py,sealed-wifi-seal.py,sealed-wifi-check.py,collect_quote.py} "$lib/"
install -m 0755 "$source_dir/setup.py" "$launcher"
install -m 0644 "$source_dir/setup.desktop" "$desktop"
printf '%s\n' "$release" >"$state/release"
printf '%s\n' "$wifi_interface" >"$state/wifi-interface"
printf '%s\n' "$staging" >"$state/staging"
cat >"$helper" <<'SH'
#!/bin/sh
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/root /usr/bin/python3 -I -B /usr/local/libexec/darkbloom-halo-setup/wizard-admin.py "$@"
SH
chmod 0755 "$helper"
for operation in status prepare-menu calibration-key calibrate calibration-report arm finish; do
    printf '%s ALL=(root) NOPASSWD: %s %s\n' "$owner" "$helper" "$operation"
done >"$state/sudoers"
chmod 0440 "$state/sudoers"
/usr/sbin/visudo -cf "$state/sudoers"
mv -- "$state/sudoers" "$grant"
committed=1
echo 'Setup wizard installed. Boot entries and credentials have not been changed.'
