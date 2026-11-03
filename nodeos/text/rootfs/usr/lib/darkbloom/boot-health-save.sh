#!/bin/sh
# Fixed root-owned sink for the bounded pre-admission report. No arguments.
set -eu
umask 027
D=/run/darkbloom
test -d "$D" && test ! -L "$D"
test "$(stat -c %u "$D")" = 0
test "$(stat -c %g "$D")" = "$(id -g)"
test "$(stat -c %a "$D")" = 750
test ! -e "$D/boot-health.json" && test ! -L "$D/boot-health.json"
T=$(mktemp "$D/.boot-health.XXXXXXXX")
trap 'rm -f "$T"' EXIT HUP INT TERM
/usr/bin/python3 -I -B /usr/lib/darkbloom/boot-health.py --pre-inference-details >"$T"
test "$(wc -c <"$T")" -le 16384
chmod 0640 "$T"
# Hard-link creation is atomic and fails if the first report already exists.
# Even an explicit service restart cannot capture logs after private requests.
ln "$T" "$D/boot-health.json"
