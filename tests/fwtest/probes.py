"""Network probe primitives. Stdlib only, used on the host, in containers,
and on the remote peer.

Probe outcomes:
  connected/answered - the target responded
  refused            - an RST or ICMP port-unreachable came back (the packet
                       reached a network stack; nothing was listening)
  timeout            - no response at all (typical for firewall DROP)
  unreachable        - local network error (no route)
  error:...          - anything else
"""

import concurrent.futures
import errno
import random
import socket
import struct

TIMEOUT = 3.0


def tcp_probe_full(host, port, timeout=TIMEOUT):
    """TCP connect; on success, read a short banner so the responder can be
    identified (all fwtest listeners announce themselves)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = None
            sock.settimeout(1.0)
            try:
                banner = sock.recv(64).decode('ascii', 'replace').strip() or None
            except (socket.timeout, TimeoutError, OSError):
                pass
            return {'outcome': 'connected', 'banner': banner}
    except (socket.timeout, TimeoutError):
        return {'outcome': 'timeout', 'banner': None}
    except ConnectionRefusedError:
        return {'outcome': 'refused', 'banner': None}
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return {'outcome': 'unreachable', 'banner': None}
        return {'outcome': f'error: {e}', 'banner': None}


def tcp_probe(host, port, timeout=TIMEOUT):
    return tcp_probe_full(host, port, timeout)['outcome']


def _dns_query(qname, qid):
    header = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    question = b''.join(
        bytes([len(label)]) + label.encode('ascii')
        for label in qname.split('.')
    ) + b'\x00'
    return header + question + struct.pack('!HH', 1, 1)  # QTYPE=A, QCLASS=IN


def _dns_response_ok(data, qid):
    if len(data) < 12:
        return False
    rid, flags = struct.unpack('!HH', data[:4])
    return rid == qid and bool(flags & 0x8000)  # QR bit: it is a response


def _udp_family(host):
    return socket.AF_INET6 if ':' in host else socket.AF_INET


def dns_udp_probe(host, port=53, timeout=TIMEOUT, qname='example.com'):
    qid = random.randrange(0x10000)
    query = _dns_query(qname, qid)
    sock = socket.socket(_udp_family(host), socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # connect() so ICMP port-unreachable surfaces as ConnectionRefusedError
        sock.connect((host, port))
        sock.send(query)
        data = sock.recv(4096)
        return 'answered' if _dns_response_ok(data, qid) else 'error: bad response'
    except (socket.timeout, TimeoutError):
        return 'timeout'
    except ConnectionRefusedError:
        return 'refused'
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return 'unreachable'
        return f'error: {e}'
    finally:
        sock.close()


def dns_tcp_probe(host, port=53, timeout=TIMEOUT, qname='example.com'):
    qid = random.randrange(0x10000)
    query = _dns_query(qname, qid)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack('!H', len(query)) + query)
            length_raw = sock.recv(2)
            if len(length_raw) < 2:
                return 'error: connection closed'
            data = sock.recv(struct.unpack('!H', length_raw)[0])
            return 'answered' if _dns_response_ok(data, qid) else 'error: bad response'
    except (socket.timeout, TimeoutError):
        return 'timeout'
    except ConnectionRefusedError:
        return 'refused'
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return 'unreachable'
        return f'error: {e}'


_KINDS = {
    'dns_udp': lambda spec: dns_udp_probe(spec['host'], spec.get('port', 53)),
    'dns_tcp': lambda spec: dns_tcp_probe(spec['host'], spec.get('port', 53)),
}


def run_one(spec):
    result = dict(spec)
    result.setdefault('banner', None)
    if spec.get('skip'):
        result['outcome'] = 'skipped: {}'.format(spec['skip'])
    elif spec['kind'] == 'tcp':
        result.update(tcp_probe_full(spec['host'], spec['port']))
    else:
        result['outcome'] = _KINDS[spec['kind']](spec)
    return result


def run_all(specs, workers=8):
    """Run probe specs concurrently, preserving order.

    A spec is a dict: {id, kind: tcp|dns_udp|dns_tcp, host, port?, skip?}.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(run_one, specs))
