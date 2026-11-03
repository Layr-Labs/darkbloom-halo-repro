#!/bin/bash
# Root-owned operator helper input: stage signed text UKI and verity images.
# Never run this x-writable script through an unrestricted NOPASSWD rule.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 022
[[ $(id -u) == 0 ]] || { echo 'Run through the approved root-owned admin helper' >&2; exit 1; }
DEVICE_CONFIG=/var/lib/darkbloom-text-e2e/device.json
DEVICE_TOOL=/usr/local/libexec/darkbloom-text-e2e/device_config.py
[[ -f $DEVICE_CONFIG && ! -L $DEVICE_CONFIG && $(stat -c %u "$DEVICE_CONFIG") == 0 ]]
config_mode=$(stat -c %a "$DEVICE_CONFIG")
(( (8#$config_mode & 0022) == 0 )) || exit 1
device_get() { python3 -I "$DEVICE_TOOL" get "$DEVICE_CONFIG" "$1"; }
[[ $(hostname) == "$(device_get hostname)" ]] || { echo 'Device hostname differs from the protected configuration' >&2; exit 1; }
WORK=${NODEOS_TEXT_WORK:?root-owned accepted bundle directory required}
WORK=$(readlink -f "$WORK")
[[ $WORK == /var/lib/darkbloom-text-e2e/bundles/* && -d $WORK && ! -L $WORK ]]
[[ $(stat -c %u "$WORK") == 0 ]]
work_mode=$(stat -c %a "$WORK")
(( (8#$work_mode & 0022) == 0 )) || exit 1
OUT=$WORK/out
ID=${ID:-$(cat "$OUT/install-id")}
[[ $ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || exit 2
ESP=$(device_get esp_mount)
ESP_DEVICE=$(device_get esp_device)
ESP_PARTUUID=$(device_get esp_partuuid)
ESP_DISK=$(device_get esp_disk)
ESP_PARTITION=$(device_get esp_partition)
FACTORY_EFI_DIR=$(device_get factory_efi_dir)
DATA=/var/lib/darkbloom-text-nodeos/$ID
EFI_DIR=$ESP/EFI/darkbloom-text/$ID
MOK_CERT=/var/lib/darkbloom-text-e2e/trust/boot-cert.der
MOK_CHECKER=/usr/local/libexec/darkbloom-text-e2e/check-mok.py
MOK_SHA256=$(device_get mok_cert_sha256)

check_esp() {
    test "$(findmnt -n --types vfat -o FSTYPE "$ESP")" = vfat
    test "$(readlink -f "$(findmnt -n --types vfat -o SOURCE "$ESP")")" = "$(readlink -f "$ESP_DEVICE")"
    test "$(blkid -s PARTUUID -o value "$ESP_DEVICE")" = "$ESP_PARTUUID"
    mokutil --sb-state | grep -qx 'SecureBoot enabled'
}
check_mok() {
    test "$(sha256sum "$MOK_CERT" | cut -d' ' -f1)" = "${MOK_SHA256,,}"
    python3 -I "$MOK_CHECKER" "$MOK_CERT"
}
case "${1:-install}" in
install)
    check_esp
    check_mok
    test ! -e "$DATA" && test ! -e "$EFI_DIR"
    test -s "$OUT/signed.efi" && test -s "$OUT/signed.efi.sha256"
    expected=$(awk 'NR==1 {print $1}' "$OUT/signed.efi.sha256")
    [[ $expected =~ ^[a-fA-F0-9]{64}$ ]]
    test "$(sha256sum "$OUT/signed.efi" | cut -d' ' -f1)" = "${expected,,}"
    # The privileged bootstrap must snapshot and approve these four literal
    # payload filenames and hashes; no path from the manifest is executed.
    python3 - "$OUT/payload.sha256" <<'PY'
from pathlib import Path
import re, sys
rows = [line.split() for line in Path(sys.argv[1]).read_text().splitlines()]
expected = {'root.erofs','root.verity','models.erofs','models.verity'}
if len(rows) != 4 or {r[1] for r in rows if len(r) == 2} != expected:
    raise SystemExit('Unexpected payload manifest filenames')
if any(len(r) != 2 or not re.fullmatch('[a-fA-F0-9]{64}',r[0]) for r in rows):
    raise SystemExit('Malformed payload manifest')
PY
    (cd "$OUT" && sha256sum -c payload.sha256)
    shim=$ESP/$FACTORY_EFI_DIR/shimx64.efi
    manager=$ESP/$FACTORY_EFI_DIR/mmx64.efi
    test -s "$shim" && test -s "$manager"
    required=$(( ($(stat -c %s "$OUT/signed.efi") + $(stat -c %s "$shim") + $(stat -c %s "$manager")) / 1024 + 16384 ))
    available=$(df -Pk "$ESP" | awk 'NR==2 {print $4}')
    test "$available" -ge "$required"
    before=$(efibootmgr | sed -n 's/^BootOrder: //p')
    [[ $before =~ ^[a-fA-F0-9]{4}(,[a-fA-F0-9]{4})*$ ]]
    old_entries=$(efibootmgr | sed -n 's/^Boot\([a-fA-F0-9]\{4\}\)[* ].*/\1/p' | sort)
    install -d -m 0755 /var/lib/darkbloom-text-nodeos "$DATA" "$EFI_DIR"
    printf '%s\n' "$before" >"$DATA/boot-order.before"
    for name in root.erofs root.verity models.erofs models.verity; do
        cp --reflink=auto "$OUT/$name" "$DATA/$name"
        chown root:root "$DATA/$name"
        chmod 0600 "$DATA/$name"
    done
    install -m 0644 "$OUT/payload.sha256" "$DATA/payload.sha256"
    (cd "$DATA" && sha256sum -c payload.sha256)
    install -m 0644 "$shim" "$EFI_DIR/shimx64.efi"
    install -m 0644 "$manager" "$EFI_DIR/mmx64.efi"
    install -m 0644 "$OUT/signed.efi" "$EFI_DIR/grubx64.efi"
    printf '%s\n' "${expected,,}" >"$DATA/uki.sha256"
    label="Darkbloom Text Node OS $ID"
    efibootmgr --create-only --disk "$ESP_DISK" --part "$ESP_PARTITION" --label "$label" --loader "\\EFI\\darkbloom-text\\$ID\\shimx64.efi"
    new_entries=$(efibootmgr | sed -n 's/^Boot\([a-fA-F0-9]\{4\}\)[* ].*/\1/p' | sort)
    entry=$(comm -13 <(printf '%s\n' "$old_entries") <(printf '%s\n' "$new_entries"))
    [[ $entry =~ ^[a-fA-F0-9]{4}$ ]]
    efibootmgr -v | grep -E "^Boot$entry[* ]" | grep -F "$label" | grep -Fi "\\EFI\\darkbloom-text\\$ID\\shimx64.efi"
    printf '%s\n' "$entry" >"$DATA/boot-id"
    after=$(efibootmgr | sed -n 's/^BootOrder: //p')
    if [[ $after != "$before" ]]; then
        # Only undo a proven side effect of our newly created entry. A concurrent
        # owner boot-order edit is preserved and requires manual reconciliation.
        if [[ ${after^^} == "${entry^^},${before^^}" ]]; then efibootmgr --bootorder "$before"; fi
        efibootmgr --bootnum "$entry" --delete-bootnum
        echo 'BootOrder changed during entry creation; removed only the new entry and failed' >&2
        exit 1
    fi
    sync
    printf 'Text Node OS staged as Boot%s; factory default unchanged. No reboot performed.\n' "$entry"
    ;;
boot-once)
    check_esp
    check_mok
    entry=$(cat "$DATA/boot-id")
    [[ $entry =~ ^[a-fA-F0-9]{4}$ ]]
    efibootmgr -v | grep -F "Boot$entry" | grep -F "Darkbloom Text Node OS $ID" | grep -Fi "\\EFI\\darkbloom-text\\$ID\\shimx64.efi"
    test "$(sha256sum "$EFI_DIR/grubx64.efi" | cut -d' ' -f1)" = "$(cat "$DATA/uki.sha256")"
    saved=$(cat "$DATA/boot-order.before")
    [[ $saved =~ ^[a-fA-F0-9]{4}(,[a-fA-F0-9]{4})*$ ]]
    # The root controller may reconcile known factory fallback aliases first;
    # this installer never silently overwrites an unrelated user boot change.
    test "$(efibootmgr | sed -n 's/^BootOrder: //p')" = "$saved"
    efibootmgr --bootnext "$entry"
    sync
    systemctl reboot
    ;;
verify)
    check_esp
    check_mok
    (cd "$DATA" && sha256sum -c payload.sha256)
    test "$(sha256sum "$EFI_DIR/grubx64.efi" | cut -d' ' -f1)" = "$(cat "$DATA/uki.sha256")"
    printf 'Installed text Node OS payload hashes match.\n'
    ;;
*) echo 'Usage: install.sh {install|boot-once|verify}' >&2; exit 2 ;;
esac
