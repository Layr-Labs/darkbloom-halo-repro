#!/bin/bash
# Rootless, private text-profile build. Does not install, enroll, or reboot.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
PROFILE=$(cd "$(dirname "$0")" && pwd)
PROJECT=$(cd "$PROFILE/../.." && pwd)
WORK=${NODEOS_TEXT_WORK:-$PROFILE/.work}
OUT=$WORK/out
KVER=${KVER:-$(uname -r)}
BUILDER=localhost/darkbloom-nodeos-text-builder
ROOTFS=localhost/darkbloom-nodeos-text-rootfs
die() { printf '%s\n' "$*" >&2; exit 1; }
DEVICE_TOOL=$PROJECT/tools/halo-e2e/device_config.py
device_get() { python3 -I "$DEVICE_TOOL" get "$1" "$2"; }
[[ ${DEBUG:-0} == 0 ]] || die 'DEBUG is forbidden for the private text profile'
[[ -z ${DEVLOG:-} ]] || die 'External debug/journal export is forbidden for the private text profile'
[[ -z ${AGENT_ARGS:-} ]] || die 'Free-form agent flags are forbidden for the private text profile'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'Build on the x86_64 Halo Linux host'
[[ $WORK == /* && $WORK != / ]] || die 'NODEOS_TEXT_WORK must be an absolute build directory'
mkdir -p "$WORK" "$OUT"
chmod 700 "$WORK"

ensure_builder() {
    podman image exists "$BUILDER" || podman build -q -t "$BUILDER" -f "$PROFILE/Containerfile.builder" "$PROFILE" >/dev/null
}
builder() { podman run --rm --network=none -v "$WORK:/work" -v "$PROJECT/nodeos:/src:ro" -w /work "$BUILDER" "$@"; }
verity() {
    builder veritysetup format --data-block-size=4096 --hash-block-size=4096 "out/$1.erofs" "out/$1.verity" >"$OUT/$1.verity.txt"
    awk '/^Root hash:/ {print $3}' "$OUT/$1.verity.txt" >"$OUT/$1.roothash"
    builder veritysetup verify "out/$1.erofs" "out/$1.verity" "$(cat "$OUT/$1.roothash")"
    printf '%s image and verity tree verified\n' "$1"
}
case "${1:-}" in
prepare)
    TEXT_WORKFLOW=${TEXT_WORKFLOW:-$PROFILE/workflow.json}
    : "${AGENT:?compatible Linux x86_64 dbnode binary}" "${COORDINATOR:?wss coordinator URL}" \
      "${CA_CERT:?coordinator CA PEM}" "${WIFI_PROFILE:?private .nmconnection file prepared by administrator}" \
      "${PAIRING_TOKEN_FILE:?private pairing-token file}" "${TEXT_MODEL:?one GGUF file}" \
      "${TEXT_MODEL_ID:?model identifier}" "${TEXT_WORKFLOW:?approved text workflow JSON}" \
      "${SYSTEMD_CORE:?reviewed confidentiality-compatible libsystemd-core-257.so}" \
      "${DEVICE_CONFIG:?explicit per-device device.json; see tools/halo-e2e}"
    python3 -I "$DEVICE_TOOL" check "$DEVICE_CONFIG"
    install -m 0600 "$DEVICE_CONFIG" "$OUT/device.json"
    DEVICE_CONFIG_SHA256=$(sha256sum "$OUT/device.json" | cut -d' ' -f1)
    SYSTEMD_EXECUTOR=${SYSTEMD_EXECUTOR:-$(dirname "$SYSTEMD_CORE")/systemd-executor}
    [[ $COORDINATOR =~ ^wss://[A-Za-z0-9.:-]+/v1/provider/ws$ ]] || die 'Only a named/direct-LAN wss:// coordinator is accepted'
    [[ $TEXT_MODEL_ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'Invalid text model ID'
    for file in "$AGENT" "$CA_CERT" "$WIFI_PROFILE" "$PAIRING_TOKEN_FILE" "$TEXT_MODEL" "$TEXT_WORKFLOW" "$SYSTEMD_CORE" "$SYSTEMD_CORE.sha256" "$SYSTEMD_EXECUTOR" "$SYSTEMD_EXECUTOR.sha256"; do test -s "$file" || die "Missing input: $file"; done
    TEXT_MAX_TOKENS=${TEXT_MAX_TOKENS:-1024}
    TEXT_CONTEXT_SIZE=${TEXT_CONTEXT_SIZE:-4096}
    TEXT_GPU_LAYERS=${TEXT_GPU_LAYERS:-99}
    TEXT_THREADS=${TEXT_THREADS:-8}
    RETURN_AFTER=${RETURN_AFTER:-25min}
    [[ $TEXT_MAX_TOKENS =~ ^[0-9]+$ && $TEXT_MAX_TOKENS -ge 1 && $TEXT_MAX_TOKENS -le 1024 ]] || die 'Text token cap must be 1..1024'
    [[ $TEXT_CONTEXT_SIZE =~ ^[0-9]+$ && $TEXT_CONTEXT_SIZE -ge 2048 && $TEXT_CONTEXT_SIZE -le 65536 ]] || die 'Invalid text context size'
    [[ $TEXT_GPU_LAYERS =~ ^[0-9]+$ && $TEXT_GPU_LAYERS -le 999 ]] || die 'Invalid GPU layer count'
    [[ $TEXT_THREADS =~ ^[0-9]+$ && $TEXT_THREADS -ge 1 && $TEXT_THREADS -le 128 ]] || die 'Invalid thread count'
    [[ $RETURN_AFTER =~ ^([0-9]{1,3})min$ ]] || die 'Return interval must be 5..120min'
    return_minutes=$((10#${BASH_REMATCH[1]}))
    (( return_minutes >= 5 && return_minutes <= 120 )) || die 'Return interval must be 5..120min'
    RETURN_AFTER=${return_minutes}min
    actual_model=$(sha256sum "$TEXT_MODEL" | cut -d' ' -f1)
    if [[ -n ${TEXT_MODEL_SHA256:-} ]]; then [[ ${TEXT_MODEL_SHA256,,} == "$actual_model" ]] || die 'Model SHA-256 differs from supplied pin'; fi
    LLAMA_VERSION=$(dpkg-query -W -f='${Version}' llama.cpp-tools)
    GGML_VERSION=$(dpkg-query -W -f='${Version}' libggml0-backend-hip)
    MICROCODE_VERSION=$(dpkg-query -W -f='${Version}' amd64-microcode)
    [[ -n $LLAMA_VERSION && -n $GGML_VERSION && -n $MICROCODE_VERSION ]] || die 'Installed AMD llama/HIP/microcode versions are required'
    SYSTEMD_PACKAGE_VERSION=$(dpkg-query -W -f='${Version}' systemd)
    [[ $SYSTEMD_PACKAGE_VERSION == 257.13-1~deb13u1 && $(dpkg-query -W -f='${Version}' libsystemd-shared) == "$SYSTEMD_PACKAGE_VERSION" ]] || die 'Patched systemd core requires exact 257.13-1~deb13u1 ABI'
    SYSTEMD_CORE_SHA256=$(sha256sum "$SYSTEMD_CORE" | cut -d' ' -f1)
    [[ $(awk 'NR==1 {print $1}' "$SYSTEMD_CORE.sha256") == "$SYSTEMD_CORE_SHA256" ]] || die 'Patched systemd core hash differs from builder output'
    SYSTEMD_EXECUTOR_SHA256=$(sha256sum "$SYSTEMD_EXECUTOR" | cut -d' ' -f1)
    [[ $(awk 'NR==1 {print $1}' "$SYSTEMD_EXECUTOR.sha256") == "$SYSTEMD_EXECUTOR_SHA256" ]] || die 'Patched systemd executor hash differs from builder output'
    python3 - "$SYSTEMD_CORE" "$SYSTEMD_EXECUTOR" <<'PY'
import pathlib, struct, sys
for source in sys.argv[1:]:
    data = pathlib.Path(source).read_bytes()[:20]
    if len(data) < 20 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0] != 62:
        raise SystemExit('Patched systemd artifacts must be ELF64 little-endian x86_64')
PY
    B=$WORK/build
    rm -rf "$B" "$WORK/nodeos"
    mkdir -p "$B/apt" "$B/keyrings" "$B/modules" "$B/systemd" "$B/generated/usr/share/darkbloom/text" "$B/secrets/etc/NetworkManager/system-connections" "$WORK/nodeos/text"
    install -m 0644 "$SYSTEMD_CORE" "$B/systemd/libsystemd-core-257.so"
    install -m 0755 "$SYSTEMD_EXECUTOR" "$B/systemd/systemd-executor"
    cp -a "$PROJECT/nodeos/rootfs" "$WORK/nodeos/rootfs"
    cp -a "$PROFILE/rootfs" "$WORK/nodeos/text/rootfs"
    # Public apt trust inputs must be readable by apt's unprivileged verifier;
    # the surrounding private build context still stays mode 0700.
    chmod 0755 "$B/apt" "$B/keyrings"
    install -m 0644 /etc/apt/sources.list.d/ryai.sources /etc/apt/sources.list.d/ryai-security.sources "$B/apt/"
    install -m 0644 /usr/share/keyrings/ryai-archive-keyring.gpg "$B/keyrings/"
    cp -a --reflink=auto "/usr/lib/modules/$KVER" "$B/modules/"
    if [[ -d /usr/lib/firmware/amd-ucode ]]; then cp -a /usr/lib/firmware/amd-ucode "$B/amd-ucode"; fi
    install -m 0755 "$AGENT" "$B/dbnode"
    install -m 0644 "$CA_CERT" "$B/generated/usr/share/darkbloom/coordinator-ca.pem"
    install -m 0644 "$TEXT_WORKFLOW" "$B/generated/usr/share/darkbloom/text/workflow.json"
    python3 - "$B/generated/usr/share/darkbloom" <<'PY'
import hashlib, json, pathlib, stat, sys
out = pathlib.Path(sys.argv[1])
base = pathlib.Path('/usr/lib/firmware/amdtee')
names = ('773bd96f-b83f-4d52-b12dc529b13d8543.bin', 'amd_pmf_v3.bin',
         'amd_pmf_v3_1.bin', 'f29bb3d9-bd66-5441-afb88acc2b2b60d6.bin')
rows, hashes = [], []
for name in names:
    path = base / name
    resolved = path.resolve(strict=True)
    info = path.stat()
    if resolved.parent != base.resolve() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('Untrusted AMD TEE firmware path or mode')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(dict(name=name,bytes=info.st_size,sha256=digest,mode=oct(info.st_mode & 0o777),
                     link=path.readlink().as_posix() if path.is_symlink() else None))
    hashes.append(f'{digest}  {path}\n')
(out/'amdtee-firmware.sha256').write_text(''.join(hashes))
(out/'amdtee-firmware.json').write_text(json.dumps(rows, sort_keys=True, indent=2)+'\n')
PY
    mkdir -p "$B/secrets/usr/share/darkbloom"
    install -m 0600 "$PAIRING_TOKEN_FILE" "$B/secrets/usr/share/darkbloom/pairing-token"
    python3 - "$WIFI_PROFILE" "$B/secrets/etc/NetworkManager/system-connections/nodeos.nmconnection" "$TEXT_WORKFLOW" <<'PY'
import configparser, json, pathlib, sys
source, output, workflow = sys.argv[1:]
json.loads(pathlib.Path(workflow).read_text())
p = configparser.ConfigParser(interpolation=None)
p.optionxform = str
p.read(source)
if not p.has_section('connection'): raise SystemExit('Wi-Fi input is not a NetworkManager keyfile')
p['connection']['permissions'] = ''
p['connection']['autoconnect'] = 'true'
security = next((s for s in ('wifi-security','802-11-wireless-security') if p.has_section(s)), None)
if security and p[security].get('key-mgmt') in ('wpa-psk','sae'):
    if not p[security].get('psk'): raise SystemExit('Wi-Fi keyfile needs its PSK; no desktop secret agent exists in Node OS')
    p[security]['psk-flags'] = '0'
with open(output, 'w') as f: p.write(f, space_around_delimiters=False)
pathlib.Path(output).chmod(0o600)
PY
    cat >"$B/generated/usr/share/darkbloom/agent.env" <<EOF
DB_COORDINATOR=$COORDINATOR
DB_TEXT_MODEL_ID=$TEXT_MODEL_ID
DB_TEXT_MODEL_SHA256=$actual_model
DB_TEXT_MAX_TOKENS=$TEXT_MAX_TOKENS
EOF
    cat >"$B/generated/usr/share/darkbloom/engine.env" <<EOF
DB_TEXT_MODEL_ID=$TEXT_MODEL_ID
DB_TEXT_CONTEXT_SIZE=$TEXT_CONTEXT_SIZE
DB_TEXT_GPU_LAYERS=$TEXT_GPU_LAYERS
DB_TEXT_THREADS=$TEXT_THREADS
EOF
    mkdir -p "$B/generated/etc/systemd/system/nodeos-return.timer.d"
    printf '[Timer]\nOnBootSec=\nOnBootSec=%s\n' "$RETURN_AFTER" >"$B/generated/etc/systemd/system/nodeos-return.timer.d/after.conf"
    printf 'NODEOS_PROFILE=text-uki\nNODEOS_KERNEL=%s\nNODEOS_MODEL_ID=%s\n' "$KVER" "$TEXT_MODEL_ID" >"$B/generated/etc/darkbloom-nodeos-release"
    # COPY preserves directory attributes. Public ancestors must remain
    # traversable by the service users; secrets keep their restrictive modes.
    find "$B/generated" "$B/secrets" -type d -exec chmod 0755 {} +
    find "$B/generated" -type f -exec chmod 0644 {} +
    chmod 0700 "$B/secrets/etc/NetworkManager/system-connections"
    chmod 0755 "$B/modules"
    python3 - "$OUT/build-inputs.json" "$TEXT_MODEL" "$actual_model" "$TEXT_MODEL_ID" "$LLAMA_VERSION" "$GGML_VERSION" "$KVER" "$RETURN_AFTER" "$MICROCODE_VERSION" "$B/generated/usr/share/darkbloom/amdtee-firmware.json" "$SYSTEMD_CORE_SHA256" "$SYSTEMD_PACKAGE_VERSION" "$SYSTEMD_EXECUTOR_SHA256" "$DEVICE_CONFIG_SHA256" <<'PY'
import json, pathlib, sys
out, model, digest, model_id, llama, ggml, kernel, return_after, microcode, firmware, systemd_core, systemd_package, systemd_executor, device_config = sys.argv[1:]
pathlib.Path(out).write_text(json.dumps(dict(profile='text-uki',model_source=str(pathlib.Path(model).resolve()),model_sha256=digest,model_id=model_id,llama_version=llama,ggml_version=ggml,kernel=kernel,return_after=return_after,microcode_version=microcode,amdtee_firmware=json.loads(pathlib.Path(firmware).read_text()),systemd_core_sha256=systemd_core,systemd_package_version=systemd_package,systemd_executor_sha256=systemd_executor,device_config_sha256=device_config),indent=2)+'\n')
PY
    printf 'out/\nmodels-stage/\n*.log\n' >"$WORK/.containerignore"
    echo 'Text inputs staged privately; no Tailscale identity or external debug channel included'
    ;;
rootfs)
    test -s "$OUT/build-inputs.json" || die 'Run prepare first'
    LLAMA_VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["llama_version"])' "$OUT/build-inputs.json")
    GGML_VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ggml_version"])' "$OUT/build-inputs.json")
    MICROCODE_VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["microcode_version"])' "$OUT/build-inputs.json")
    SYSTEMD_CORE_SHA256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["systemd_core_sha256"])' "$OUT/build-inputs.json")
    SYSTEMD_EXECUTOR_SHA256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["systemd_executor_sha256"])' "$OUT/build-inputs.json")
    podman build -t "$ROOTFS" --build-arg LLAMA_VERSION="$LLAMA_VERSION" --build-arg GGML_VERSION="$GGML_VERSION" --build-arg MICROCODE_VERSION="$MICROCODE_VERSION" --build-arg SYSTEMD_CORE_SHA256="$SYSTEMD_CORE_SHA256" --build-arg SYSTEMD_EXECUTOR_SHA256="$SYSTEMD_EXECUTOR_SHA256" -f "$PROFILE/Containerfile" "$WORK"
    podman run --rm --network=none --user=dbnode "$ROOTFS" /bin/sh -eu -c '
        test -x /usr/lib/darkbloom/dbnode
        test -r /usr/share/darkbloom/coordinator-ca.pem
        test -r /usr/share/darkbloom/text/workflow.json
        test -r /usr/share/darkbloom/pairing-token
        test -x /usr/share/darkbloom/models
    '
    podman run --rm --network=none --user=dbengine "$ROOTFS" /bin/sh -eu -c '
        test -x /usr/bin/llama-server
        test -x /usr/share/darkbloom/models
        test -r /usr/share/darkbloom/engine.env
        test -r /usr/share/darkbloom/agent.env
        test -r /usr/lib/darkbloom/engine/check-network.py
    '
    ctr=$(podman create "$ROOTFS" /bin/true)
    podman export -o "$OUT/rootfs.tar" "$ctr"
    podman rm "$ctr" >/dev/null
    ensure_builder
    rm -f "$OUT/root.erofs"
    builder mkfs.erofs --quiet --tar=f out/root.erofs out/rootfs.tar
    rm -f "$OUT/rootfs.tar"
    verity root
    ;;
models)
    test -s "$OUT/build-inputs.json" || die 'Run prepare first'
    model=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["model_source"])' "$OUT/build-inputs.json")
    expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["model_sha256"])' "$OUT/build-inputs.json")
    [[ $(sha256sum "$model" | cut -d' ' -f1) == "$expected" ]] || die 'Source model changed after prepare'
    rm -rf "$WORK/models-stage"
    mkdir -p "$WORK/models-stage/text"
    chmod 0755 "$WORK/models-stage" "$WORK/models-stage/text"
    cp --reflink=auto "$model" "$WORK/models-stage/text/model.gguf"
    chmod 0644 "$WORK/models-stage/text/model.gguf"
    ensure_builder
    rm -f "$OUT/models.erofs"
    builder mkfs.erofs --quiet --all-root out/models.erofs models-stage
    verity models
    ;;
initrd)
    ensure_builder
    ucode=()
    [[ ! -d $WORK/build/amd-ucode ]] || ucode=(/work/build/amd-ucode)
    builder sh /src/initrd/mkinitrd.sh "$KVER" "/work/build/modules/$KVER" /src/text/init out/initrd.img "${ucode[0]:-}" sha384
    python3 "$PROJECT/nodeos/initrd/check-sha384-initrd.py" "$OUT/initrd.img"
    sha256sum "$OUT/initrd.img"
    ;;
options)
    : "${ID:?release/install ID}"
    [[ $ID =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || die 'Invalid install ID'
    test -s "$OUT/device.json" && test -s "$OUT/build-inputs.json" || die 'Run prepare with an explicit DEVICE_CONFIG first'
    expected_config=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["device_config_sha256"])' "$OUT/build-inputs.json")
    [[ $(sha256sum "$OUT/device.json" | cut -d' ' -f1) == "$expected_config" ]] || die 'Prepared device configuration changed'
    HOST_PARTUUID=$(device_get "$OUT/device.json" host_partuuid)
    HOST_ROOT_UUID=$(device_get "$OUT/device.json" host_root_uuid)
    D=/var/lib/darkbloom-text-nodeos/$ID
    printf '%s\n' "nodeos.host-partuuid=$HOST_PARTUUID nodeos.host-uuid=$HOST_ROOT_UUID nodeos.root=$D/root.erofs nodeos.roottree=$D/root.verity roothash=$(cat "$OUT/root.roothash") nodeos.models=$D/models.erofs nodeos.modelstree=$D/models.verity nodeos.modelshash=$(cat "$OUT/models.roothash") rdinit=/init lockdown=confidentiality debugfs=off iommu.strict=1 module.sig_enforce=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none systemd.gpt_auto=0 rd.systemd.gpt_auto=0 panic=10 quiet loglevel=4" >"$OUT/options"
    printf '%s\n' "$ID" >"$OUT/install-id"
    cat "$OUT/options"
    ;;
uki)
    test -s "$OUT/options" && test -s "$OUT/initrd.img" || die 'Run initrd and options first'
    ensure_builder
    cp "/boot/vmlinuz-$KVER" "$OUT/linux"
    ID=$(cat "$OUT/install-id")
    printf 'NAME="Darkbloom text Node OS"\nID=darkbloom-nodeos\nVERSION_ID="%s"\n' "$ID" >"$OUT/os-release"
    printf 'sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\nuki.darkbloom.text,1,Darkbloom,uki.darkbloom.text,1,https://github.com/Layr-Labs/darkbloom-amd\n' >"$OUT/sbat.csv"
    builder ukify build --linux=out/linux --initrd=out/initrd.img --stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub \
        --os-release=@out/os-release --cmdline=@out/options --uname="$KVER" --sbat=@out/sbat.csv --output=out/unsigned.efi
    (cd "$OUT" && sha256sum root.erofs root.verity models.erofs models.verity >payload.sha256 && sha256sum unsigned.efi >unsigned.efi.sha256)
    printf 'Unsigned text UKI ready at %s; sign on the Mac only.\n' "$OUT/unsigned.efi"
    ;;
*)
    echo "Usage: $0 {prepare|rootfs|models|initrd|options|uki}" >&2
    exit 2
    ;;
esac
