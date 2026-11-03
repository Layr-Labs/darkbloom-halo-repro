#!/usr/bin/env bash
# Exercise the text engine's exact preflight and nft policy in a disposable
# rootless Podman network namespace. No host firewall state is changed.
set -euo pipefail
[[ $(uname -s) == Linux && $EUID -ne 0 ]] || { echo 'Run as an ordinary Linux user' >&2; exit 1; }
command -v podman >/dev/null
PROJECT=$(cd "$(dirname "$0")/../../.." && pwd)
POLICY=$PROJECT/nodeos/text/rootfs/etc/nftables.conf
CHECK=$PROJECT/nodeos/text/rootfs/usr/lib/darkbloom/engine/check-network.py
IMAGE=${1:-localhost/darkbloom-nodeos-text-rootfs}
[[ -r $POLICY && -r $CHECK ]] || { echo 'Missing reviewed policy or checker' >&2; exit 1; }
podman image exists "$IMAGE" || { echo "Missing rootfs test image: $IMAGE" >&2; exit 1; }
podman run --rm --network none --cap-add NET_ADMIN \
    -v "$POLICY:/tmp/review-nftables.conf:ro" \
    -v "$CHECK:/tmp/check-network.py:ro" \
    --entrypoint /bin/sh "$IMAGE" -c '
set -eu
ip link add dbtest type dummy
ip addr add 192.0.2.2/24 dev dbtest
ip link set dbtest up
printf "DB_COORDINATOR=wss://192.0.2.1:8790/v1/provider/ws\n" >/usr/share/darkbloom/agent.env
if setpriv --reuid=dbengine --regid=dbjobs --clear-groups /usr/bin/python3 -I /tmp/check-network.py; then
    echo "FAIL: checker passed without firewall" >&2; exit 1
fi
echo "PASS: absent firewall rejected"
/usr/sbin/nft -f /tmp/review-nftables.conf
setpriv --reuid=dbengine --regid=dbjobs --clear-groups /usr/bin/python3 -I /tmp/check-network.py
echo "PASS: reviewed firewall accepted"
ip link del dbtest
if setpriv --reuid=dbengine --regid=dbjobs --clear-groups /usr/bin/python3 -I /tmp/check-network.py; then
    echo "FAIL: checker passed without route" >&2; exit 1
fi
echo "PASS: absent route rejected"
'
