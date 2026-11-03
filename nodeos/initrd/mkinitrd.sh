#!/bin/sh
# Assembles the Node OS initrd (runs inside the builder container):
#   mkinitrd.sh KVER MODULES_DIR INIT OUT [UCODE_DIR] [sha384]
# MODULES_DIR is /usr/lib/modules/KVER of the AMD-signed kernel; UCODE_DIR
# (optional) holds AMD's signed CPU microcode (amd64-microcode), prepended
# as the early-load cpio exactly as the owner's Debian initrd does. The initrd
# holds a static busybox, veritysetup with its libraries, the init script
# and the signed modules for NVMe, btrfs, loop, dm-verity, erofs, overlayfs
# and the SP5100 TCO watchdog. The optional sha384 mode adds the signed
# sha512 module and a narrow /sbin/modprobe helper for the kernel's early
# IMA SHA384 TPM-bank autoload, before userspace /init runs. It is opt-in so
# callers that omit it retain the basic module set. Timestamps and
# ownership are normalized so the same inputs give the same initrd (its
# SHA-256 is measured into PCR 9).
set -eu
KVER=$1 MODS=$2 INIT=$3 OUT=$4 UCODE=${5:-} CRYPTO_AUTOLOAD=${6:-}
case "$CRYPTO_AUTOLOAD" in ''|sha384) ;; *) echo "unsupported early crypto autoload: $CRYPTO_AUTOLOAD" >&2; exit 1 ;; esac
T=$(mktemp -d)
MODROOT=$(mktemp -d)
trap 'rm -rf "$T" "$MODROOT"' EXIT
mkdir -p "$T/bin" "$T/sbin" "$T/etc" "$T/dev" "$T/proc" "$T/sys" "$T/run" "$T/newroot" \
	"$T/lib/modules" "$T/lib/x86_64-linux-gnu" "$T/lib64"

cp /bin/busybox "$T/bin/busybox"
for a in $(/bin/busybox --list); do
	[ "$a" = busybox ] || ln -sf busybox "$T/bin/$a"
done

copy_with_libs() {
	cp "$1" "$T/sbin/"
	ldd "$1" | awk '/=> \// {print $3} /^\t\/lib64\// {print $1}' | while read -r lib; do
		d=$(dirname "$lib")
		case "$d" in /usr/lib/*) d=/lib/${d#/usr/lib/} ;; esac
		mkdir -p "$T$d"
		cp -L "$lib" "$T$d/"
	done
}
copy_with_libs /usr/sbin/veritysetup

mkdir -p "$MODROOT/lib/modules"
ln -s "$MODS" "$MODROOT/lib/modules/$KVER"
: >"$T/etc/nodeos-modules"
for m in nvme btrfs loop dm_verity erofs overlay sp5100_tco; do
	modprobe -d "$MODROOT" -S "$KVER" --show-depends "$m"
done | awk '$1 == "insmod" {print $2}' | awk '!seen[$0]++' | while read -r path; do
	f=$MODS${path#*/lib/modules/$KVER}
	base=$(basename "$f")
	case "$base" in
	*.ko.xz) xz -dc "$f" >"$T/lib/modules/${base%.xz}" && base=${base%.xz} ;;
	*.ko.zst) zstd -qdc "$f" >"$T/lib/modules/${base%.zst}" && base=${base%.zst} ;;
	*.ko) cp "$f" "$T/lib/modules/" ;;
	*) echo "unexpected module file $f" >&2 && exit 1 ;;
	esac
	echo "$base" >>"$T/etc/nodeos-modules"
done
echo "initrd modules:" >&2
sed 's/^/  /' "$T/etc/nodeos-modules" >&2

if [ "$CRYPTO_AUTOLOAD" = sha384 ]; then
	# IMA initializes during kernel initcalls, after the initramfs is unpacked
	# but before /init can load modules. The crypto API invokes the kernel's
	# CONFIG_MODPROBE_PATH (/sbin/modprobe here) for crypto-sha384. The
	# factory kernel builds that transform in signed sha512.ko, not built-in.
	sha512="$MODS/kernel/crypto/sha512.ko.xz"
	[ -r "$sha512" ] || { echo "signed SHA512 module missing: $sha512" >&2; exit 1; }
	xz -dc "$sha512" >"$T/lib/modules/sha512.ko"
	chmod 0644 "$T/lib/modules/sha512.ko"
	# Compressed modules are signed before compression. Reject an unsigned
	# build input instead of relying solely on the boot-time module gate.
	[ "$(tail -c 28 "$T/lib/modules/sha512.ko")" = '~Module signature appended~' ] || {
		echo "SHA512 module has no appended kernel signature" >&2; exit 1;
	}
	cp "$(dirname "$0")/modprobe-sha384" "$T/sbin/modprobe"
	chmod 0755 "$T/sbin/modprobe"
	echo "early IMA SHA384 autoload: signed sha512.ko" >&2
fi

cp "$INIT" "$T/init"
chmod 0755 "$T/init"
find "$T" -exec touch -h -d @0 {} +
: >"$OUT"
if [ -n "$UCODE" ]; then
	E=$(mktemp -d)
	mkdir -p "$E/kernel/x86/microcode"
	cat "$UCODE"/microcode_amd*.bin >"$E/kernel/x86/microcode/AuthenticAMD.bin"
	find "$E" -exec touch -h -d @0 {} +
	(cd "$E" && find . -mindepth 1 | LC_ALL=C sort | cpio --quiet -o -H newc --owner=0:0 --reproducible) >"$OUT"
	rm -rf "$E"
	echo "early microcode: $(cat "$UCODE"/microcode_amd*.bin | wc -c) bytes" >&2
fi
(cd "$T" && find . -mindepth 1 | LC_ALL=C sort | cpio --quiet -o -H newc --owner=0:0 --reproducible) | gzip -9 -n >>"$OUT"
echo "wrote $OUT ($(wc -c <"$OUT") bytes)" >&2
