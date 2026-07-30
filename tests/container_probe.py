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


def detect_self_ip(gateway):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect() on UDP sends nothing; it just selects the source IP
        sock.connect((gateway or '192.0.2.1', 9))
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


def run_listen(spec):
    for port in spec.get('tcp_ports', []):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(8)
        threading.Thread(target=_accept_loop, args=(server,), daemon=True).start()
    print('READY', flush=True)
    threading.Event().wait()


def run_probe(spec):
    gateway = detect_gateway()
    env = {'gateway': gateway, 'self_ip': detect_self_ip(gateway),
           'nameservers': detect_nameservers()}
    expanded = []
    for p in spec:
        p = dict(p)
        if p.get('host') == '@gateway':
            if env['gateway']:
                p['host'] = env['gateway']
            else:
                p['skip'] = 'no default gateway detected in container'
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
