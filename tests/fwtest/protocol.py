"""JSON-lines control protocol between the test orchestrators and
remote_peer.py."""

import json
import socket

CONTROL_PORT = 65510      # orchestrator <-> remote_peer control channel
PORT_PEER_PROBE = 65511   # peer listener: the container -> LAN egress target


def send(fp, obj):
    fp.write((json.dumps(obj) + '\n').encode('utf-8'))
    fp.flush()


def recv(fp):
    line = fp.readline()
    if not line:
        return None
    return json.loads(line.decode('utf-8'))


class PeerControl:
    """Client side of the control channel served by remote_peer.py."""

    def __init__(self, host, port=CONTROL_PORT):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(30)
        self.fp = self.sock.makefile('rwb')

    def call(self, **msg):
        send(self.fp, msg)
        resp = recv(self.fp)
        if not resp or not resp.get('ok'):
            raise RuntimeError(f'peer error for {msg!r}: {resp!r}')
        return resp

    def close(self):
        try:
            send(self.fp, {'cmd': 'quit'})
        except OSError:
            pass
        self.sock.close()
