#!/bin/bash
# Root-owned lifecycle only: fixed unit, fixed paths, no prompt or owner input.
# The unprivileged model process never receives write access to control markers.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 027
CTL=/run/dbnode-control
UNIT=dbnode-llama.service
[[ $(id -u) == 0 && -d $CTL && ! -L $CTL ]]
stop() { systemctl stop "$UNIT" >/dev/null 2>&1 || true; exit 0; }
trap stop TERM INT
gen=0
notified=0
if [[ -f $CTL/engine.gen ]]; then
    read -r previous previous_pid <"$CTL/engine.gen" || true
    if [[ ${previous:-} =~ ^[0-9]{1,12}$ ]]; then gen=$((10#$previous)); fi
fi
rm -f "$CTL/engine.gen"
while true; do
    rm -f "$CTL/restart"
    # Restart is synchronous: PID 1 tears down the complete old cgroup first.
    systemctl restart "$UNIT"
    ready=0
    for ((attempt=0; attempt<1200; attempt++)); do
        pid=$(systemctl show --property=MainPID --value "$UNIT")
        if [[ $pid =~ ^[1-9][0-9]*$ ]] && curl --noproxy '*' --max-time 1 --fail --silent --output /dev/null http://127.0.0.1:8080/health; then
            ready=1
            break
        fi
        systemctl is-active --quiet "$UNIT" || break
        sleep 1
    done
    [[ $ready == 1 ]] || { systemctl stop "$UNIT"; sleep 1; continue; }
    gen=$((gen + 1))
    temporary=$(mktemp "$CTL/.generation.XXXXXX")
    printf '%s %s\n' "$gen" "$pid" >"$temporary"
    chmod 0640 "$temporary"
    mv -fT "$temporary" "$CTL/engine.gen"
    if [[ $notified == 0 ]]; then
        /usr/bin/systemd-notify --ready
        notified=1
    fi
    while [[ ! -e $CTL/restart ]] && systemctl is-active --quiet "$UNIT"; do sleep 0.2; done
done
