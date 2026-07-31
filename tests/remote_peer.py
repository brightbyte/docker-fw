#!/usr/bin/env python3
"""Cross-host test helper. Run this unprivileged on a SECOND machine on the
same LAN as the host under test, then run cross_host_tests.py <this-ip>
over there.

The orchestrator drives this script over a JSON-lines TCP control channel
(default port 65510). If the peer runs UFW, open the test ports with
`sudo tests/ufw_setup.sh` (the same script used on the host opens the peer
ports too); undo with `ufw_teardown.sh`.

This is an unauthenticated test tool: it accepts commands from the address
given via --allow-from (or, failing that, from the first client to connect).
Always pass --allow-from: it is the access control for the channel, since
ufw_setup.sh opens the port to any address. Stop it with Ctrl-C.
"""

import argparse
import json
import socket
import sys
import threading
import time

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwtest import probes, protocol
from fwtest.protocol import CONTROL_PORT


class RecordingListener:
    """TCP listener (both address families) that records every accepted
    connection."""

    def __init__(self, port):
        self.port = port
        self.connections = []  # list of {source, time}
        self.servers = []
        for family, addr in ((socket.AF_INET, '0.0.0.0'),
                             (socket.AF_INET6, '::')):
            server = socket.socket(family, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                server.bind((addr, port))
            except OSError:
                if family == socket.AF_INET6:
                    continue   # no IPv6 here; v4 listener still records
                raise
            server.listen(8)
            self.servers.append(server)
            threading.Thread(target=self._accept_loop, args=(server,),
                             daemon=True).start()

    def _accept_loop(self, server):
        while True:
            try:
                conn, addr = server.accept()
            except OSError:
                return
            self.connections.append({'source': addr[0], 'time': time.time()})
            print(f'  connection on port {self.port} from {addr[0]}')
            try:
                conn.sendall(b'fwtest-peer\n')
            except OSError:
                pass
            conn.close()

    def close(self):
        for server in self.servers:
            server.close()


def detect_own_ip(target):
    """The address this machine would use to talk to target (or, without a
    target, to the internet); connect() on UDP sends nothing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target or '192.0.2.1', 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def detect_own_ip6():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect(('2606:4700:4700::1111', 9))
        ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    import ipaddress
    return None if ipaddress.ip_address(ip).is_link_local else ip


class Peer:
    def __init__(self):
        self.listeners = {}

    def handle(self, msg):
        cmd = msg.get('cmd')
        if cmd == 'hello':
            return {'ok': True, 'version': 1,
                    'ip': detect_own_ip(None), 'ip6': detect_own_ip6()}
        if cmd == 'listen':
            port = int(msg['port'])
            if port not in self.listeners:
                try:
                    self.listeners[port] = RecordingListener(port)
                except OSError as e:
                    return {'ok': False, 'error': f'{e} (another process may '
                            f'be using port {port}; a stale remote_peer.py?)'}
            return {'ok': True}
        if cmd == 'connections':
            listener = self.listeners.get(int(msg['port']))
            if not listener:
                return {'ok': False, 'error': 'not listening on that port'}
            return {'ok': True, 'connections': listener.connections}
        if cmd == 'probe':
            outcome = probes.tcp_probe(msg['host'], int(msg['port']))
            print('  probed {}:{} -> {}'.format(msg['host'], msg['port'], outcome))
            return {'ok': True, 'outcome': outcome}
        if cmd == 'reset':
            for listener in self.listeners.values():
                listener.connections.clear()
            return {'ok': True}
        if cmd == 'quit':
            return {'ok': True, 'quit': True}
        return {'ok': False, 'error': f'unknown command {cmd!r}'}

    def close(self):
        for listener in self.listeners.values():
            listener.close()
        self.listeners.clear()


def serve(args):
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control.bind(('0.0.0.0', args.control_port))
    control.listen(1)
    allow_from = args.allow_from
    print(f'remote_peer: control channel on port {args.control_port}')
    own_ip = detect_own_ip(allow_from)
    if own_ip:
        print(f"This machine's IP address (enter this at the "
              f'cross_host_tests.py prompt): {own_ip}')
    own_ip6 = detect_own_ip6()
    if own_ip6:
        print(f"This machine's IPv6 address: {own_ip6}")
    print('If UFW is active on this machine, open the test ports (the same '
          'setup script used on the host opens the peer ports too):')
    print('    sudo tests/ufw_setup.sh          (undo with ufw_teardown.sh)')
    print('Waiting for the orchestrator; stop with Ctrl-C.')

    # One Peer for the process lifetime: listeners persist across control
    # sessions so a re-run reuses the bound sockets instead of rebinding
    # (which would fail with "address already in use"). Per-run connection
    # records are cleared by the 'reset' command at the start of each run.
    peer = Peer()
    try:
        while True:
            conn, addr = control.accept()
            if allow_from is None:
                allow_from = addr[0]
                print(f'locking control channel to first client: {allow_from}')
            if addr[0] != allow_from:
                print(f'rejecting control connection from {addr[0]}')
                conn.close()
                continue
            print(f'orchestrator connected from {addr[0]}')
            fp = conn.makefile('rwb')
            try:
                while True:
                    msg = protocol.recv(fp)
                    if msg is None:
                        break
                    try:
                        resp = peer.handle(msg)
                    except (KeyError, ValueError) as e:
                        resp = {'ok': False, 'error': f'bad message: {e}'}
                    protocol.send(fp, resp)
                    if resp.get('quit'):
                        break
            except (OSError, json.JSONDecodeError) as e:
                print(f'control channel error: {e}')
            finally:
                conn.close()
                print('session ended; waiting for the next one (Ctrl-C to stop)')
    finally:
        peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-port', type=int, default=CONTROL_PORT)
    parser.add_argument('--allow-from', metavar='IP',
                        help='only accept control connections from this IP '
                             '(default: lock to the first client)')
    args = parser.parse_args()
    try:
        serve(args)
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
