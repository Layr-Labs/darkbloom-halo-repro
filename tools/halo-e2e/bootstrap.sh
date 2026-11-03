#!/bin/bash
# Run only from a separately SHA-256-verified, newly extracted root-owned archive.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
[[ $(id -u) == 0 && ! -L $0 ]] || { echo 'Root-owned bootstrap required' >&2; exit 1; }
REPO=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
LIB=/usr/local/libexec/darkbloom-text-e2e
STATE=/var/lib/darkbloom-text-e2e
HELPER=/usr/local/sbin/darkbloom-text-e2e-control
GRANT=/etc/sudoers.d/darkbloom-text-e2e
CONFIG=$REPO/inputs/device.json
CERT=$REPO/inputs/boot-cert.der
DEVICE_PY=$REPO/tools/halo-e2e/device_config.py

for command in /usr/bin/efibootmgr /usr/sbin/blkid /usr/sbin/visudo /usr/bin/findmnt /usr/bin/mokutil /usr/bin/openssl /usr/bin/python3 /usr/bin/bash /usr/bin/systemctl /usr/bin/install /usr/bin/mktemp /usr/bin/stat /usr/bin/sha256sum /usr/bin/env /usr/bin/id /usr/bin/getent /usr/bin/hostname /usr/bin/grep /usr/bin/cut /usr/bin/cat /usr/bin/mv /usr/bin/rm /usr/bin/rmdir /usr/bin/chmod /usr/bin/dirname /usr/bin/awk /usr/bin/sed /usr/bin/sort /usr/bin/comm /usr/bin/df /usr/bin/cp /usr/bin/chown /usr/bin/readlink /usr/bin/sync; do
    [[ -f $command && -x $command ]] || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
for trusted in /usr /usr/local /usr/local/sbin /var /var/lib /etc /etc/sudoers.d "$REPO" "$REPO/tools" "$REPO/tools/halo-e2e" "$REPO/tools/tpm" "$REPO/nodeos" "$REPO/nodeos/text" "$REPO/inputs"; do
    [[ -d $trusted && ! -L $trusted && $(stat -c %u "$trusted") == 0 ]]
    mode=$(stat -c %a "$trusted")
    (( (8#$mode & 0022) == 0 ))
done
for source in tools/halo-e2e/bootstrap.sh tools/halo-e2e/control.py tools/halo-e2e/bundle.py tools/halo-e2e/device_config.py tools/halo-e2e/check-mok.py nodeos/text/install.sh tools/tpm/read_ek_chain.py tools/tpm/collect_quote.py inputs/device.json inputs/boot-cert.der; do
    path=$REPO/$source
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 ]]
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 ))
done
[[ ! -e $LIB && ! -L $LIB && ! -e $STATE && ! -L $STATE && ! -e $HELPER && ! -L $HELPER && ! -e $GRANT && ! -L $GRANT ]] || { echo 'Protected install already exists; refusing replacement' >&2; exit 1; }

/usr/bin/python3 -I "$DEVICE_PY" check "$CONFIG"
cfg() { /usr/bin/python3 -I "$DEVICE_PY" get "$CONFIG" "$1"; }
HOST=$(cfg hostname)
OWNER=$(cfg owner_user)
ESP_MOUNT=$(cfg esp_mount)
ESP_DEVICE=$(cfg esp_device)
ESP_UUID=$(cfg esp_partuuid)
HOST_PARTUUID=$(cfg host_partuuid)
HOST_ROOT_UUID=$(cfg host_root_uuid)
FACTORY_DIR=$(cfg factory_efi_dir)
MOK_SHA=$(cfg mok_cert_sha256)
[[ $(hostname) == "$HOST" && $(id -u "$OWNER") != 0 ]]
[[ $(getent passwd "$OWNER" | cut -d: -f6) == "/home/$OWNER" && -d /home/$OWNER ]]
for mount_path in /boot "$ESP_MOUNT"; do
    [[ $mount_path != /boot || $ESP_MOUNT == /boot/efi ]] || continue
    [[ -d $mount_path && ! -L $mount_path && $(stat -c %u "$mount_path") == 0 ]]
    mode=$(stat -c %a "$mount_path")
    (( (8#$mode & 0022) == 0 ))
done
[[ -b $ESP_DEVICE && -b $(cfg esp_disk) ]]
[[ $(readlink -f "$(findmnt -n --types vfat -o SOURCE "$ESP_MOUNT")") == "$(readlink -f "$ESP_DEVICE")" ]]
[[ $(/usr/sbin/blkid -s PARTUUID -o value "$ESP_DEVICE") == "$ESP_UUID" ]]
[[ $(/usr/sbin/blkid -s UUID -o value "/dev/disk/by-partuuid/$HOST_PARTUUID") == "$HOST_ROOT_UUID" ]]
[[ $(sha256sum "$CERT" | cut -d' ' -f1) == "$MOK_SHA" ]]
/usr/bin/openssl x509 -inform DER -in "$CERT" -noout >/dev/null
/usr/bin/mokutil --sb-state | grep -qx 'SecureBoot enabled'
/usr/bin/python3 -I "$REPO/tools/halo-e2e/check-mok.py" "$CERT" >/dev/null
[[ -s $ESP_MOUNT/$FACTORY_DIR/shimx64.efi && -s $ESP_MOUNT/$FACTORY_DIR/mmx64.efi ]]
[[ ! -e $ESP_MOUNT/EFI/darkbloom-text && ! -L $ESP_MOUNT/EFI/darkbloom-text ]]

TEMP=$(mktemp -d /var/lib/.darkbloom-text-bootstrap.XXXXXX)
committed=0 new_libexec=0 new_lib=0 new_state=0 new_helper=0 new_grant=0
finish() {
    result=$?
    trap - EXIT
    set +e
    if [[ $committed != 1 ]]; then
        [[ $new_grant != 1 ]] || rm -f -- "$GRANT"
        [[ $new_helper != 1 ]] || rm -f -- "$HELPER"
        [[ $new_lib != 1 ]] || rm -rf -- "$LIB"
        [[ $new_state != 1 ]] || rm -rf -- "$STATE"
        [[ $new_libexec != 1 ]] || rmdir -- /usr/local/libexec
    fi
    rm -rf -- "$TEMP"
    exit "$result"
}
trap finish EXIT
[[ ! -L /usr/local/libexec ]]
if [[ ! -e /usr/local/libexec ]]; then install -d -m 0755 /usr/local/libexec; new_libexec=1; fi
[[ -d /usr/local/libexec && $(stat -c %u /usr/local/libexec) == 0 ]]
mode=$(stat -c %a /usr/local/libexec)
(( (8#$mode & 0022) == 0 ))
install -d -m 0755 "$TEMP/lib"
install -d -m 0700 "$TEMP/state" "$TEMP/state/trust" "$TEMP/state/bundles"
install -m 0644 "$REPO/tools/halo-e2e/control.py" "$REPO/tools/halo-e2e/bundle.py" "$REPO/tools/halo-e2e/device_config.py" "$REPO/tools/halo-e2e/check-mok.py" "$REPO/tools/tpm/read_ek_chain.py" "$REPO/tools/tpm/collect_quote.py" "$TEMP/lib/"
install -m 0755 "$REPO/nodeos/text/install.sh" "$TEMP/lib/install.sh"
install -m 0600 "$CONFIG" "$TEMP/state/device.json"
install -m 0600 "$CERT" "$TEMP/state/trust/boot-cert.der"
openssl x509 -inform DER -in "$TEMP/state/trust/boot-cert.der" -pubkey -noout > "$TEMP/state/trust/boot-public.pem"

# The exported read-only quote helper predates UKI PCR 11. Patch only its one
# exact reviewed PCR list in the protected copy; refuse any other source.
python3 -I - "$TEMP/lib/collect_quote.py" "$TEMP/state" "$ESP_MOUNT" "$FACTORY_DIR" <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, sys
p, state, esp, factory_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
s = p.read_text()
old = 'QUOTED_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 14]'
assert s.count(old) == 1, 'Unexpected quote helper source'
p.write_text(s.replace(old, 'QUOTED_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 14]'))
text = subprocess.check_output(['/usr/bin/efibootmgr', '-v'], text=True)
m = re.search(r'^BootOrder: ([0-9A-Fa-f]{4}(?:,[0-9A-Fa-f]{4})*)$', text, re.M)
assert m, 'No valid original BootOrder'
order = m[1].upper().split(',')
entries = {r[1].upper():r[2] for r in re.finditer(r'^Boot([0-9A-Fa-f]{4})\*?\s+(.*)$', text, re.M)}
assert all(entry in entries for entry in order), 'BootOrder contains absent entry'
(state/'original-boot.json').write_text(json.dumps({'order':order, 'entries':{entry:entries[entry] for entry in order}})+'\n')
files = {}
for path in sorted(esp.rglob('*')):
    rel = path.relative_to(esp).as_posix()
    if path.is_file() and not path.is_symlink() and not rel.lower().startswith('efi/darkbloom-text/') and rel.lower() != 'loader/random-seed':
        files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
assert f'{factory_dir}/shimx64.efi' in files and f'{factory_dir}/mmx64.efi' in files
(state/'factory-files.json').write_text(json.dumps(files, sort_keys=True)+'\n')
(state/'sequence.json').write_text('{"sequence":0}\n')
PY

cat > "$TEMP/helper" <<'WRAPPER'
#!/bin/sh
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C HOME=/root /usr/bin/python3 -I -B /usr/local/libexec/darkbloom-text-e2e/control.py "$@"
WRAPPER
chmod 0755 "$TEMP/helper"
for operation in status ek-chain 'quote *' wifi-profile install boot cleanup; do
    printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/darkbloom-text-e2e-control %s\n' "$OWNER" "$operation"
done > "$TEMP/grant"
chmod 0440 "$TEMP/grant"
/usr/sbin/visudo -cf "$TEMP/grant"

new_lib=1; mv -- "$TEMP/lib" "$LIB"
new_state=1; mv -- "$TEMP/state" "$STATE"
new_helper=1; mv -- "$TEMP/helper" "$HELPER"
"$HELPER" status
new_grant=1; mv -- "$TEMP/grant" "$GRANT"
committed=1
echo 'Installed fixed root operations. No payloads, boot entries, or reboot were performed.'
