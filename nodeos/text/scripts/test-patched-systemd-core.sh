#!/usr/bin/env bash
# Disposable, ordinary-user Podman test of the patched systemd core.
# It never installs a unit on the Halo host or into the sealed Node OS.
set -euo pipefail
export LC_ALL=C
umask 077
[[ $(uname -s) == Linux && $EUID -ne 0 ]] || { echo 'Run as an ordinary Linux user' >&2; exit 1; }
CORE=${1:?usage: test-patched-systemd-core.sh /ABS/PATH/libsystemd-core-257.so}
[[ $CORE == /* && -s $CORE ]] || { echo 'Core must be an absolute existing file' >&2; exit 1; }
EXECUTOR=${CORE%/*}/systemd-executor
[[ -s $EXECUTOR ]] || { echo 'Adjacent patched systemd-executor is required' >&2; exit 1; }
command -v podman >/dev/null
T=$(mktemp -d "${TMPDIR:-/tmp}/db-systemd-core-test.XXXXXX")
NAME=db-systemd-core-test-$$
IMAGE=localhost/db-systemd-core-test:$$
cleanup() { podman rm -f "$NAME" >/dev/null 2>&1 || :; podman rmi -f "$IMAGE" >/dev/null 2>&1 || :; rm -rf "$T"; }
trap cleanup EXIT
cp "$CORE" "$T/libsystemd-core-257.so"
cp "$EXECUTOR" "$T/systemd-executor"
cat >"$T/Containerfile" <<'EOF'
FROM docker.io/library/debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus && rm -rf /var/lib/apt/lists/*
COPY libsystemd-core-257.so /usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-257.so
COPY systemd-executor /usr/lib/systemd/systemd-executor
RUN test "$(dpkg-query -W -f='${Version}' systemd)" = '257.13-1~deb13u1' \
 && test "$(dpkg-query -W -f='${Version}' libsystemd-shared)" = '257.13-1~deb13u1' \
 && ldd /usr/lib/systemd/systemd | grep -q libsystemd-core-257.so \
 && ldd /usr/lib/systemd/systemd-executor | grep -q libsystemd-core-257.so \
 && /usr/lib/systemd/systemd --version | grep -q '+BPF_FRAMEWORK'
RUN printf '[Unit]\nDescription=Synthetic fail-closed BPF policy test\n[Service]\nType=oneshot\nRestrictFileSystems=~proc\nExecStart=/usr/bin/true\n' > /etc/systemd/system/db-deny.service
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
EOF
printf 'lockdown=confidentiality\n' >"$T/cmdline"
podman build -q -t "$IMAGE" "$T" >/dev/null
podman run --rm -d --name "$NAME" --systemd=always --network=none \
    --env SYSTEMD_LOG_TARGET=console --env SYSTEMD_LOG_LEVEL=info \
    --mount "type=bind,src=$T/cmdline,dst=/proc/cmdline,ro=true" \
    "$IMAGE" >/dev/null
ready=0
for _ in {1..30}; do
    if podman exec "$NAME" systemctl list-units --no-pager >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
done
[[ $ready == 1 ]] || { podman logs --tail=40 "$NAME" >&2; echo 'Nested systemd did not start' >&2; exit 1; }
[[ $(podman exec "$NAME" cat /proc/cmdline) == lockdown=confidentiality ]] || { echo 'Fake signed command line did not mount' >&2; exit 1; }
podman exec "$NAME" grep -q 'libsystemd-core-257.so' /proc/1/maps || {
    echo 'Patched core not loaded by nested PID 1' >&2; exit 1;
}
podman exec "$NAME" systemd-run --wait --unit=db-control.service /usr/bin/true >/dev/null
if podman exec "$NAME" systemctl start db-deny.service >"$T/deny-output" 2>&1; then
    cat "$T/deny-output" >&2
    podman exec "$NAME" systemctl show -p RestrictFileSystems -p Result -p ExecMainStatus db-deny.service >&2 || :
    podman exec "$NAME" journalctl -b --no-pager -g 'db-deny|RestrictFileSystems|bpf-restrict' >&2 || :
    echo 'RestrictFileSystems unit unexpectedly executed' >&2; exit 1
fi
status=$(podman exec "$NAME" systemctl show -P ExecMainStatus db-deny.service)
[[ $status == 244 ]] || { echo "Expected EXIT_BPF=244, got $status" >&2; exit 1; }
printf 'PASS: patched core loaded; ordinary unit ran; RestrictFileSystems unit failed with EXIT_BPF=244.\n'
printf 'NOTE: rootless container does not persist early PID 1 logs; the actual sealed boot must confirm the confidentiality probe is skipped.\n'
