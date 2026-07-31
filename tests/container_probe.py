#!/usr/bin/env python3
"""Test agent that runs inside the probe container image.

Modes:
  listen '{"tcp_ports": [65502, 65503]}'
      Listen on the given TCP ports, send a short banner to every client,
      print READY, and run until killed.

  probe '[{"id": ..., "kind": tcp|dns_udp|dns_tcp, "host": ..., "port": ...}, ...]'
      Run the probes and print a JSON object {"env": ..., "results": [...]}.
      The special host value "@gateway" is replaced with the container's
      default gateway (the bridge address, i.e. the host).
"""

import ipaddress
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwtest import probes


def detect_gateway():
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                # destination 0.0.0.0 with the RTF_GATEWAY flag set
                if len(fields) > 3 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(int(fields[2], 16).to_bytes(4, 'little'))
    except (OSError, ValueError):
        pass
    return None


def detect_gateway6():
    # /proc/net/ipv6_route columns: dest prefixlen src srclen nexthop metric
    # refcnt use flags iface. The default route has an all-zero destination
    # with prefixlen 0 and the RTF_GATEWAY flag (0x0002) set. Link-local
    # gateways (the common case) need a zone id to be usable as a probe
    # target, so qualify them with the route's interface.
    try:
        with open('/proc/net/ipv6_route') as f:
            for line in f:
                fields = line.split()
                if len(fields) < 10:
                    continue
                dest, plen, nexthop, flags = (fields[0], fields[1],
                                              fields[4], int(fields[8], 16))
                if dest == '0' * 32 and plen == '00' and flags & 0x2:
                    packed = bytes.fromhex(nexthop)
                    if packed != b'\x00' * 16:
                        addr = socket.inet_ntop(socket.AF_INET6, packed)
                        if ipaddress.ip_address(addr).is_link_local:
                            addr = f'{addr}%{fields[9]}'
                        return addr
    except (OSError, ValueError):
        pass
    return None


def detect_self_ip(gateway):
    return _self_ip(socket.AF_INET, gateway or '192.0.2.1')


def detect_self_ip6():
    # the target only steers the routing lookup (no packet is sent); a global
    # literal works regardless of whether the default gateway is link-local
    ip = _self_ip(socket.AF_INET6, '2606:4700:4700::1111')
    # a link-local source (fe80::/10) is not a routable address; treat the
    # container as having no usable IPv6 in that case
    if ip and ip.lower().startswith('fe80'):
        return None
    return ip


def _self_ip(family, target):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        # connect() on UDP sends nothing; it just selects the source IP
        sock.connect((target, 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def detect_nameservers():
    servers = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver':
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


def _accept_loop(server):
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        try:
            conn.sendall(b'fwtest\n')
        except OSError:
            pass
        conn.close()


def _listen_on(family, addr, port):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        # keep the v4 and v6 binds independent so they don't collide
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        server.bind((addr, port))
    except OSError:
        return  # family unavailable in this container; skip it
    server.listen(8)
    threading.Thread(target=_accept_loop, args=(server,), daemon=True).start()


def run_listen(spec):
    for port in spec.get('tcp_ports', []):
        _listen_on(socket.AF_INET, '0.0.0.0', port)
        _listen_on(socket.AF_INET6, '::', port)
    print('READY', flush=True)
    threading.Event().wait()


def run_probe(spec):
    gateway = detect_gateway()
    gateway6 = detect_gateway6()
    env = {'gateway': gateway, 'self_ip': detect_self_ip(gateway),
           'gateway6': gateway6, 'self_ip6': detect_self_ip6(),
           'nameservers': detect_nameservers()}
    placeholders = {'@gateway': ('gateway', 'no default gateway detected in container'),
                    '@gateway6': ('gateway6', 'no IPv6 default gateway in container')}
    expanded = []
    for p in spec:
        p = dict(p)
        placeholder = placeholders.get(p.get('host'))
        if placeholder:
            key, reason = placeholder
            if env[key]:
                p['host'] = env[key]
            else:
                p['skip'] = reason
        expanded.append(p)
    results = probes.run_all(expanded)
    print(json.dumps({'env': env, 'results': results}), flush=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('listen', 'probe'):
        print('usage: container_probe.py listen|probe [JSON-SPEC]', file=sys.stderr)
        return 2
    spec = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    if sys.argv[1] == 'listen':
        run_listen(spec or {})
    else:
        run_probe(spec or [])
    return 0


if __name__ == '__main__':
    sys.exit(main())
