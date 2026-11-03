#!/usr/bin/python3
"""Prove local inference and non-loopback policy in the engine sandbox.

The listener is bound to this host's route-selected LAN address. A refused,
timed-out, or unrouteable connection cannot stand in for a policy denial.
"""
import errno
import ipaddress
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit


def endpoint():
    rows = Path('/usr/share/darkbloom/agent.env').read_text().splitlines()
    values = [r.removeprefix('DB_COORDINATOR=') for r in rows if r.startswith('DB_COORDINATOR=')]
    if len(values) != 1:
        raise ValueError('coordinator origin is missing')
    url = urlsplit(values[0])
    host = ipaddress.ip_address(url.hostname or '')
    if url.scheme != 'wss' or host.is_loopback or host.is_unspecified or host.is_multicast:
        raise ValueError('a non-loopback coordinator IP is required for the policy check')
    return str(host), url.port or 443


def check_loopback():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(2)
        with socket.create_connection(listener.getsockname(), timeout=2):
            peer, _ = listener.accept()
            peer.close()


def route_source(target):
    host, port = target
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    # A UDP connect chooses a source address without sending a datagram or
    # opening a connection to the coordinator.
    with socket.socket(family, socket.SOCK_DGRAM) as route:
        route.connect((host, port))
        source = route.getsockname()[0]
    local = ipaddress.ip_address(source)
    if local.is_loopback or local.is_unspecified or local.is_multicast:
        raise ValueError('no non-loopback source address')
    return family, source


def check_nonloopback_denied(target):
    family, source = route_source(target)
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((source, 0))
        listener.listen(1)
        local_target = listener.getsockname()
        try:
            with socket.create_connection(local_target, timeout=2):
                pass
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EPERM, errno.EHOSTUNREACH):
                raise RuntimeError('non-loopback access was not demonstrably denied') from None
            # Reject a disappearing route masquerading as a policy denial.
            if route_source(target) != (family, source):
                raise RuntimeError('non-loopback source changed during check')
            return
    raise RuntimeError('engine can connect to a non-loopback listener')


def main():
    if len(sys.argv) != 1:
        return 2
    try:
        check_loopback()
        check_nonloopback_denied(endpoint())
    except (OSError, ValueError, RuntimeError):
        print('Engine network confinement check failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
