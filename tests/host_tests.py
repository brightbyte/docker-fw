#!/usr/bin/env python3
"""Probe a running system for the security outcomes promised by
ufw/after.rules (see the top-level README) and report verdicts.

Run ufw_setup.sh once first (it opens the ports these tests expect to be
reachable and backs up the ufw rules), then run unprivileged on the host:

    sudo tests/ufw_setup.sh         # once, before testing
    python3 tests/host_tests.py [--engine docker|podman|sudo-podman]
                                [--no-internet] [--json]
    sudo tests/ufw_teardown.sh      # once, when done

Inbound exposure to the LAN cannot be tested from the host itself; that is
a separate script, tests/cross_host_tests.py, run against a second machine.

--engine podman is plain (rootless) podman; --engine sudo-podman is the
rootful engine. All engines are probed with the same tests and judged by
the same verdict rules; only the explanations and hints differ.

The runs themselves never change firewall state (that is ufw_setup.sh /
ufw_teardown.sh); they warn if the setup has not run or looks stale.
Container engine commands may be run via sudo where unavoidable
(sudo-podman, or docker without socket access); every command is echoed
before use.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwtest import probes, report
from fwtest.report import (Finding, SECURE, INSECURE, OK, RESTRICTED,
                           INCONCLUSIVE, SKIPPED, INFO)
from fwtest.ufw import (PORT_HOST_OPEN, PORT_PUBLISHED_OPEN,
                        require_setup, teardown_reminder)

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE = 'docker-fw-test'
LISTENER_NAME = 'fwtest-listener'

PORT_HOST_BLOCKED = 65500   # host listener, wildcard bind: must stay blocked
PORT_HOST_LOOPBACK = 65501  # host listener, 127.0.0.1 bind: must be unreachable
PORT_PUBLISHED = 65502      # published by container A: must stay blocked
PORT_C2C = 65503            # container A internal: container-to-container test
# PORT_HOST_OPEN (65504) and PORT_PUBLISHED_OPEN (65505) are opened by
# ufw_setup.sh; the runners check they are reachable (the escape hatches).
# The peer ports (65510 control, 65511 probe) live in fwtest.protocol.

INTERNET_TCP = ('1.1.1.1', 443)
INTERNET_DNS = '9.9.9.9'
INTERNET_TCP6 = '[2606:4700:4700::1111]:443'   # Cloudflare, v6 literal

RFC1918 = [ipaddress.ip_network(n)
           for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]


def run(cmd, capture=False, check=True, timeout=None, echo=True):
    if echo:
        print('  $ ' + ' '.join(cmd), file=sys.stderr)
    return subprocess.run(cmd, stdout=subprocess.PIPE if capture else None,
                          text=True, check=check, timeout=timeout)


def quiet(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


# --- engine handling ---------------------------------------------------------

class Engine:
    def __init__(self, name, base, flavor):
        self.name = name            # docker | podman
        self.base = base
        self.flavor = flavor        # docker | podman | sudo-podman
        self.bridge_prefix = name   # interface prefix used in the rules
        # quoted so the union annotation is never evaluated at runtime
        # (safe on Python < 3.10, where bare "bool | None" would not be)
        self.rootless: "bool | None" = None   # detected after construction

    def cmd(self, *args):
        return self.base + list(args)


def available_engines():
    available = []
    if shutil.which('docker'):
        available.append('docker')
    if shutil.which('podman'):
        available += ['podman', 'sudo-podman']
    return available


def choose_engine_name(args):
    available = available_engines()
    if args.engine:
        if args.engine not in available:
            sys.exit(f'engine {args.engine!r} not available on this system')
        return args.engine
    if not available:
        sys.exit('neither docker nor podman found')
    if len(available) == 1:
        print(f'Using {available[0]} (the only engine found).')
        return available[0]
    if not sys.stdin.isatty():
        sys.exit('more than one engine available ({}); pass --engine'.format(', '.join(available)))
    while True:
        answer = input('Test which engine? [{}] '.format('/'.join(available))).strip()
        if answer in available:
            return answer


def make_engine(flavor):
    if flavor == 'podman':
        # plain podman: normally the rootless engine
        return Engine('podman', ['podman'], flavor)
    if flavor == 'sudo-podman':
        print('NOTE: rootful podman requires root; podman commands will be '
              'run via sudo.')
        return Engine('podman', ['sudo', 'podman'], flavor)
    usable = False
    if shutil.which('docker'):
        p = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        usable = p.returncode == 0
    if not usable:
        print('NOTE: docker is not usable without privileges here; docker '
              'commands will be run via sudo.')
        return Engine('docker', ['sudo', 'docker'], flavor)
    return Engine('docker', ['docker'], flavor)


def engine_is_rootless(engine):
    if engine.name == 'docker':
        p = run(engine.cmd('info', '--format', '{{json .SecurityOptions}}'),
                capture=True, check=False, echo=False)
        return 'rootless' in (p.stdout or '')
    p = run(engine.cmd('info', '--format', '{{.Host.Security.Rootless}}'),
            capture=True, check=False, echo=False)
    return (p.stdout or '').strip() == 'true'


# --- host environment --------------------------------------------------------

class HostEnv:
    def __init__(self, probe_internet=True):
        self.gateway, self.lan_iface = self._default_route()
        self.lan_ip = self._lan_ip()
        self.gateway6 = self._default_route6()
        self.lan_ip6 = self._lan_ip6()
        self.ipv6 = self.lan_ip6 is not None
        # whether the host itself can reach the internet. If the host can't,
        # neither can a container (it routes through the host), so the
        # container internet checks become uninformative. Used only to
        # interpret those results, never to assert a v6 block is real. None
        # means "not probed" (--no-internet, or no host v6 for internet6).
        self.internet4 = self._internet4() if probe_internet else None
        self.internet6 = (self._internet6()
                          if self.ipv6 and probe_internet else None)
        self.dns_servers = self._dns_servers()
        self.lan_dns = [ip for ip in self.dns_servers if self._is_rfc1918(ip)]
        self.loopback_dns = [ip for ip in self.dns_servers
                             if ipaddress.ip_address(ip).is_loopback]
        self.rules_installed = self._rules_installed()

    @staticmethod
    def _is_rfc1918(ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RFC1918)

    @staticmethod
    def _default_route():
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines()[1:]:
                    fields = line.split()
                    # destination 0.0.0.0 with the RTF_GATEWAY flag set
                    if len(fields) > 3 and fields[1] == '00000000' \
                            and int(fields[3], 16) & 2:
                        gateway = socket.inet_ntoa(
                            int(fields[2], 16).to_bytes(4, 'little'))
                        return gateway, fields[0]
        except (OSError, ValueError):
            pass
        return None, None

    def _lan_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # connect() on UDP sends nothing; it just selects the source IP
            sock.connect((self.gateway or '192.0.2.1', 9))
            return sock.getsockname()[0]
        except OSError:
            return None
        finally:
            sock.close()

    @staticmethod
    def _default_route6():
        # /proc/net/ipv6_route: default route has an all-zero destination with
        # prefixlen 0 and the RTF_GATEWAY flag (0x0002) set. IPv6 default
        # gateways are typically link-local; those need a zone id to be a
        # usable address, so qualify them with the route's interface.
        try:
            with open('/proc/net/ipv6_route') as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    dest, plen, nexthop = fields[0], fields[1], fields[4]
                    if dest == '0' * 32 and plen == '00' \
                            and int(fields[8], 16) & 0x2:
                        packed = bytes.fromhex(nexthop)
                        if packed != b'\x00' * 16:
                            addr = socket.inet_ntop(socket.AF_INET6, packed)
                            if ipaddress.ip_address(addr).is_link_local:
                                addr = f'{addr}%{fields[9]}'
                            return addr
        except (OSError, ValueError):
            pass
        return None

    def _lan_ip6(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            # the target only steers the routing lookup (no packet is sent);
            # a global literal works regardless of whether the default
            # gateway is a link-local address
            sock.connect(('2606:4700:4700::1111', 9))
            ip = sock.getsockname()[0]
        except OSError:
            return None
        finally:
            sock.close()
        # a link-local source means there is no routable IPv6 on this host
        return None if ipaddress.ip_address(ip).is_link_local else ip

    @staticmethod
    def _internet4():
        return probes.tcp_probe(INTERNET_TCP[0], INTERNET_TCP[1]) == 'connected'

    @staticmethod
    def _internet6():
        host, port = INTERNET_TCP6.rsplit(':', 1)
        return probes.tcp_probe(host.strip('[]'), int(port)) == 'connected'

    @staticmethod
    def _dns_servers():
        servers = []
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == 'nameserver':
                        servers.append(parts[1])
        except OSError:
            pass
        stub = any(ipaddress.ip_address(s).is_loopback for s in servers
                   if not s.startswith('fe80'))
        if stub and shutil.which('resolvectl'):
            # systemd-resolved stub; ask it for the real upstreams
            p = run(['resolvectl', 'dns'], capture=True, check=False, echo=False)
            servers += re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', p.stdout or '')
        seen, result = set(), []
        for s in servers:
            try:
                addr = ipaddress.ip_address(s)
            except ValueError:
                continue
            if addr.version == 4 and s not in seen:
                seen.add(s)
                result.append(s)
        return result

    @staticmethod
    def _rules_installed():
        try:
            with open('/etc/ufw/after.rules') as f:
                return 'DOCKER-USER' in f.read()
        except OSError:
            return None

    def print_summary(self, engine):
        print()
        print('Environment:')
        print('  engine:          {} ({})'.format(engine.flavor, ' '.join(engine.base)))
        print('  rootless:        %s' % ('yes' if engine.rootless else 'no'))
        reach = {True: 'yes', False: 'no', None: 'not probed'}
        print(f'  LAN interface:   {self.lan_iface}, IP {self.lan_ip}')
        print(f'  default gateway: {self.gateway}')
        print(f'  internet (v4):   {reach[self.internet4]}')
        if self.ipv6:
            print(f'  IPv6 address:    {self.lan_ip6}')
            print(f'  IPv6 gateway:    {self.gateway6}')
            print(f'  IPv6 internet:   {reach[self.internet6]}')
        else:
            print('  IPv6:            not available on this host')
        print('  DNS servers:     %s' % (', '.join(self.dns_servers) or 'none detected'))
        installed = {True: 'yes', False: 'NO', None: 'unknown (file not readable)'}
        print(f'  after.rules has DOCKER-USER markers: {installed[self.rules_installed]}')
        print()


# --- host listeners ----------------------------------------------------------

def _accept_loop(server):
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        try:
            conn.sendall(b'fwtest-host\n')
        except OSError:
            pass
        conn.close()


class HostListeners:
    # (family, address, port). The wildcard ports also get a v6 bind so the
    # IPv6 "must be blocked" probes have a live target to distinguish a
    # firewall drop from nothing-listening.
    BINDS = [(socket.AF_INET,  '0.0.0.0',   PORT_HOST_BLOCKED),
             (socket.AF_INET6, '::',        PORT_HOST_BLOCKED),
             (socket.AF_INET,  '127.0.0.1', PORT_HOST_LOOPBACK),
             (socket.AF_INET6, '::1',       PORT_HOST_LOOPBACK),
             (socket.AF_INET,  '0.0.0.0',   PORT_HOST_OPEN),
             (socket.AF_INET6, '::',        PORT_HOST_OPEN)]

    def __init__(self):
        self.servers = []
        for family, addr, port in self.BINDS:
            server = socket.socket(family, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                server.bind((addr, port))
            except OSError as e:
                if family == socket.AF_INET6:
                    continue   # no IPv6 on this host; v6 probes will SKIP
                sys.exit(f'cannot listen on {addr}:{port}: {e} (another test '
                         'running, or the port is in use?)')
            server.listen(8)
            threading.Thread(target=_accept_loop, args=(server,),
                             daemon=True).start()
            self.servers.append(server)

    def close(self):
        for server in self.servers:
            server.close()


# --- container plumbing ------------------------------------------------------

def ensure_image(engine, rebuild):
    if not rebuild and quiet(engine.cmd('image', 'inspect', IMAGE)).returncode == 0:
        return
    run(engine.cmd('build', '-t', IMAGE, TESTS_DIR))


# A dedicated dual-stack network, so containers get a routable IPv6 address and
# the IPv6 tests actually run (the default bridge has no IPv6 unless the daemon
# is configured for it). Its interface is br-* (docker) or podman<N> (podman),
# both matched by the after.rules br+/podman+ prefixes; ufw_setup.sh opens the
# escape-hatch port on br+ too.
TEST_NETWORK = 'fwtest-net'
TEST_NETWORK_V6_SUBNET = 'fd00:f005:ba11::/64'
_network_ready = False


def ensure_test_network(engine):
    """Create the dual-stack test network if absent. Returns True if we
    created it this run (so the caller removes it afterwards), False if it
    already existed or could not be created. Best-effort: on failure the
    containers fall back to the default bridge and the IPv6 tests skip."""
    global _network_ready
    if quiet(engine.cmd('network', 'inspect', TEST_NETWORK)).returncode == 0:
        _network_ready = True
        return False
    if engine.name == 'podman':
        cmd = engine.cmd('network', 'create', '--ipv6', TEST_NETWORK)
    else:
        cmd = engine.cmd('network', 'create', '--ipv6',
                         '--subnet', TEST_NETWORK_V6_SUBNET, TEST_NETWORK)
    if quiet(cmd).returncode != 0:
        print(f'NOTE: could not create the IPv6 test network ({TEST_NETWORK}); '
              'IPv6 tests will be skipped. Enable IPv6 in the engine (for '
              'docker, "ipv6": true and "ip6tables": true in daemon.json) to '
              'test them.', file=sys.stderr)
        _network_ready = False
        return False
    _network_ready = True
    return True


def remove_test_network(engine):
    quiet(engine.cmd('network', 'rm', TEST_NETWORK))


def _network_args():
    return ['--network', TEST_NETWORK] if _network_ready else []


def start_listener_container(engine):
    quiet(engine.cmd('rm', '-f', LISTENER_NAME))
    spec = json.dumps({'tcp_ports': [PORT_PUBLISHED, PORT_PUBLISHED_OPEN,
                                     PORT_C2C]})
    run(engine.cmd('run', '-d', '--rm', '--name', LISTENER_NAME,
                   *_network_args(),
                   '-p', f'{PORT_PUBLISHED}:{PORT_PUBLISHED}',
                   '-p', f'{PORT_PUBLISHED_OPEN}:{PORT_PUBLISHED_OPEN}',
                   IMAGE, 'listen', spec), capture=True)
    for _ in range(15):
        p = run(engine.cmd('logs', LISTENER_NAME),
                capture=True, check=False, echo=False)
        if 'READY' in (p.stdout or ''):
            break
        time.sleep(1)
    else:
        sys.exit('listener container did not become ready')
    p = run(engine.cmd('inspect', LISTENER_NAME), capture=True, echo=False)
    settings = json.loads(p.stdout)[0]['NetworkSettings']

    def pick(*keys):
        for key in keys:
            if settings.get(key):
                return settings[key]
        for net in settings.get('Networks', {}).values():
            for key in keys:
                if net.get(key):
                    return net[key]
        return None

    return pick('IPAddress'), pick('GlobalIPv6Address')


def run_container_probes(engine, spec):
    """Run container_probe.py in a throwaway container; return (env, results-by-id)."""
    p = run(engine.cmd('run', '--rm', *_network_args(), IMAGE, 'probe',
                       json.dumps(spec)),
            capture=True, timeout=120 + 4 * len(spec))
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    data = json.loads(lines[-1])
    return data['env'], {r['id']: r for r in data['results']}


# --- verdict helpers ---------------------------------------------------------

def verdict_blocked(outcome, refused_means_reached):
    """Verdict for a probe whose target must NOT be reachable."""
    if outcome == 'connected':
        return INSECURE
    if outcome == 'timeout':
        return SECURE
    if outcome == 'refused':
        return INSECURE if refused_means_reached else INCONCLUSIVE
    if outcome.startswith('skipped'):
        return SKIPPED
    return INCONCLUSIVE


def verdict_allowed(outcome):
    """Verdict for a probe whose target SHOULD be reachable."""
    if outcome in ('connected', 'answered'):
        return OK
    if outcome.startswith('skipped'):
        return SKIPPED
    if outcome in ('timeout', 'refused', 'unreachable'):
        return RESTRICTED
    return INCONCLUSIVE


def install_actions():
    return ['Install the rules: sudo cp ufw/after.rules /etc/ufw/after.rules '
            '&& sudo ufw reload',
            'Inspect the live chains: sudo iptables -L DOCKER-USER -v -n; '
            'sudo iptables -L ufw-after-input -v -n']


def containment_actions(engine):
    if engine.rootless:
        return ['Rootless engines cannot be confined by after.rules (see the '
                'Caveats section of the top-level README). For containment, '
                'run the workload under a rootful engine: --engine docker or '
                '--engine sudo-podman.']
    return install_actions()


def describe(res):
    if res.get('banner'):
        return '{} (banner: {})'.format(res['outcome'], res['banner'])
    return res['outcome']


REFUSED_MEANING = (
    'The connection was actively rejected rather than dropped: either a '
    'REJECT firewall rule intervened (which still blocks the path), or the '
    'packet reached a closed port on some network stack. after.rules uses '
    'DROP and logs "[UFW DOCKER BLOCK]"; check the ufw log to tell the '
    'cases apart.')

MAP_GW_HINT = (
    "If this engine uses pasta (rootless podman default), this is the "
    "gateway-to-loopback mapping; disable it with --no-map-gw via "
    "network_cmd_options in containers.conf.")


# --- phase 1: baseline -------------------------------------------------------

def baseline_findings(results, env, host, engine):
    prefix = engine.bridge_prefix
    if engine.rootless:
        allow_hint = (f'Interface-scoped ufw rules ({prefix}+) cannot match rootless '
                      'traffic; to reach host services from rootless '
                      'containers use pasta --map-gw or slirp4netns '
                      'allow_host_loopback.')
    else:
        allow_hint = ('To deliberately allow one port: sudo ufw allow in on '
                      f'{prefix}+ to any port <PORT>')
    findings = []

    def result(fid):
        return results.get(fid, {'outcome': 'skipped: probe not run'})

    def reached_meaning(res):
        if res.get('banner') == 'fwtest-host':
            return ('The test listener on this host answered: any code '
                    'running in a container can connect to services on '
                    'this host.')
        return ('Something at this address accepted the connection, but not '
                'this host\'s test listener; the address may belong to a '
                'different machine (e.g. the LAN gateway). Either way, '
                'container traffic escaped containment.')

    for fid, target in (('host-gw',
                         f'its gateway address {env.get("gateway")}'),
                        ('host-lan', f'host LAN IP {host.lan_ip}')):
        res = result(fid)
        title = f'Container -> {target} (host test port {PORT_HOST_BLOCKED})'
        if fid == 'host-lan' and env.get('self_ip') \
                and env['self_ip'] == host.lan_ip:
            # user-mode stacks (pasta) copy the host address into the
            # container; the connection never leaves the container
            findings.append(Finding(
                fid, title, INCONCLUSIVE,
                observed='the probe container itself holds this address',
                meaning='The container carries the host\'s LAN IP (a '
                        'user-mode network stack copies the host address '
                        'into the container), so this connection never '
                        'leaves the container namespace and the host cannot '
                        'be probed via this address.'))
            continue
        verdict = verdict_blocked(res['outcome'], refused_means_reached=False)
        meaning = {
            SECURE: 'Containers cannot reach host services via this address.',
            INSECURE: reached_meaning(res),
            INCONCLUSIVE: REFUSED_MEANING,
        }.get(verdict, '')
        actions = containment_actions(engine) if verdict == INSECURE \
            else [allow_hint]
        findings.append(Finding(fid, title, verdict, observed=describe(res),
                                meaning=meaning, actions=actions))

    res = result('host-lo')
    outcome = res['outcome']
    if outcome == 'connected':
        confirmed = res.get('banner') == 'fwtest-host'
        actions = containment_actions(engine)
        if engine.rootless:
            actions = [MAP_GW_HINT] + actions
        findings.append(Finding(
            'host-lo',
            f'Container -> loopback-bound host service (port {PORT_HOST_LOOPBACK})',
            INSECURE, observed=describe(res),
            meaning='A service bound only to 127.0.0.1 on the host was '
                    'reachable from a container: something redirects '
                    'container traffic to the host loopback interface.'
                    + (' The banner confirms it is this host that answered.'
                       if confirmed else ''),
            actions=actions))
    else:
        findings.append(Finding(
            'host-lo',
            f'Container -> loopback-bound host service (port {PORT_HOST_LOOPBACK})',
            SECURE if outcome in ('timeout', 'refused') else INCONCLUSIVE,
            observed=outcome,
            meaning='Services bound only to 127.0.0.1 are not reachable from '
                    'containers. (A "refused" here means address binding '
                    f'protected the service; the port-{PORT_HOST_BLOCKED} '
                    'results show whether the firewall drop is active too.)'))

    # escape hatch: ufw_setup.sh opened this host port to containers, so it
    # must now be reachable (the counterpart to the blocked ports above)
    res = result('host-open')
    findings.append(Finding(
        'host-open',
        f'Container -> host escape-hatch port {PORT_HOST_OPEN} (opened by setup)',
        verdict_allowed(res['outcome']), observed=describe(res),
        meaning='The documented escape hatch works: a host port opened with '
                '"ufw allow in on docker+/podman+" is reachable from '
                'containers.'
        if res['outcome'] == 'connected' else
        f'Host port {PORT_HOST_OPEN} is not reachable from containers. Either '
        'ufw_setup.sh has not run, or the container bridge interface does not '
        'match the docker+/podman+ prefixes the allow rule uses.',
        actions=[] if res['outcome'] == 'connected' else
        ['Run: sudo tests/ufw_setup.sh',
         'Check the interface name with: ip -o link']))

    outcome = result('c2c')['outcome']
    if outcome == 'connected':
        c2c_meaning = 'Containers on the bridge can communicate, as intended.'
        c2c_actions = []
    elif outcome.startswith('skipped'):
        c2c_meaning = ('No IP address was detected for the listener '
                       'container, so there is no direct container-to-'
                       'container path to probe. Rootless engines default to '
                       'per-container user-mode networking (pasta) without a '
                       'shared bridge; containers then reach each other only '
                       'via ports published on the host.')
        c2c_actions = ['To probe direct container traffic, put both '
                       'containers on a shared network (podman network '
                       'create). Note that a rootless bridge lives inside '
                       'the user namespace; its traffic never crosses the '
                       'host firewall.']
    else:
        c2c_meaning = ('Container-to-container traffic is blocked; that '
                       'breaks multi-container applications.')
        c2c_actions = [f'Check the "-i {prefix}+ -o {prefix}+ -j RETURN" rules in the '
                       'DOCKER-USER section of /etc/ufw/after.rules']
    findings.append(Finding(
        'c2c', f'Container -> container (port {PORT_C2C})',
        verdict_allowed(outcome), observed=outcome,
        meaning=c2c_meaning, actions=c2c_actions))

    for fid, res in sorted(results.items()):
        if not fid.startswith('dns-'):
            continue
        outcome = res['outcome']
        findings.append(Finding(
            fid, 'Container -> DNS server {} ({})'.format(res['host'], res['kind']),
            verdict_allowed(outcome), observed=outcome,
            meaning='The port-53 carve-out works; containers can resolve names.'
            if outcome == 'answered' else
            'Containers cannot use this DNS server. Either the carve-out '
            'rules are missing, or the server refuses queries from this '
            'subnet.',
            actions=[] if outcome == 'answered' else
            ['Check the port-53 ACCEPT rules in /etc/ufw/after.rules']))
    if not host.lan_dns:
        findings.append(Finding(
            'dns-none', 'Container -> DNS on host or LAN', SKIPPED,
            meaning='No RFC-1918 DNS server detected on this host (resolver: '
                    '%s). The port-53 carve-out could not be probed.'
                    % (', '.join(host.dns_servers) or 'none')))

    for fid, port in (('router-80', 80), ('router-443', 443)):
        if fid not in results:
            continue
        res = results[fid]
        # refused is NOT treated as reached: the RST/ICMP could equally come
        # from a REJECT-style firewall rule on this host, which protects just
        # as well as DROP; the origin is not observable from the container
        verdict = verdict_blocked(res['outcome'], refused_means_reached=False)
        actions = []
        if verdict == INSECURE:
            actions = containment_actions(engine)
            if engine.rootless:
                actions = ['Note: with pasta --map-gw, gateway-addressed '
                           'traffic is redirected to the host itself; the '
                           'response may come from the host, not the '
                           'router.'] + actions
        elif verdict == SECURE:
            actions = ['To deliberately allow LAN access for containers, add '
                       'explicit ACCEPT rules to the DOCKER-USER section']
        if verdict == SECURE:
            meaning = 'Containers cannot reach other machines on the LAN.'
        elif verdict == INSECURE:
            meaning = ('Container traffic reached a network stack at the LAN '
                       'gateway address; code running in containers can leave '
                       'its confinement.')
        elif res['outcome'] == 'refused':
            meaning = ('The connection was rejected. That can mean the packet '
                       'reached the gateway and hit a closed port (traffic '
                       'escaped containment), or that a REJECT-style firewall '
                       'rule on this host answered (traffic was blocked); the '
                       'origin of the rejection is not observable from the '
                       'container. after.rules uses DROP, so with these rules '
                       'active the expected outcome is a timeout. '
                       'tests/cross_host_tests.py settles this question by '
                       'observing arrivals on another machine.')
        else:
            meaning = (f'The probe did not produce a usable observation '
                       f'({res["outcome"]}).')
        findings.append(Finding(
            fid, f'Container -> LAN gateway {host.gateway} (port {port})',
            verdict, observed=describe(res), meaning=meaning, actions=actions))

    # container -> internet: expected reachable. If the host itself has no
    # internet, the container can't either, so skip rather than report a
    # misleading RESTRICTED.
    if host.internet4 is False:
        findings.append(Finding(
            'inet', 'Container -> internet', SKIPPED,
            observed='host has no internet route',
            meaning='This host cannot reach the internet, so the container '
                    'internet-access check is not meaningful.'))
    else:
        for fid, label in (('inet-tcp', f'{INTERNET_TCP[0]}:{INTERNET_TCP[1]} tcp'),
                           ('inet-dns', f'{INTERNET_DNS}:53 udp')):
            if fid not in results:
                continue
            outcome = results[fid]['outcome']
            findings.append(Finding(
                fid, f'Container -> internet ({label})',
                verdict_allowed(outcome), observed=outcome,
                meaning='Containers can reach the public internet, as intended.'
                if verdict_allowed(outcome) == OK else
                'Containers have no internet access even though the host does; '
                f'check the "-i {engine.bridge_prefix}+ -j RETURN" rules in '
                'DOCKER-USER.'))

    # informational: host -> published port takes a different firewall path
    outcome = probes.tcp_probe(host.lan_ip or '127.0.0.1', PORT_PUBLISHED)
    findings.append(Finding(
        'host-published',
        f'Host itself -> published container port {PORT_PUBLISHED}',
        INFO, observed=outcome,
        meaning='Traffic originating on the host does not traverse the '
                'container inbound rules; reachability from the host says '
                'nothing about exposure to the LAN. Run '
                'tests/cross_host_tests.py for the real inbound test.'))
    return findings


SECTION_V6 = 'Baseline (IPv6)'


def _v6_block(outcome, positive):
    """Verdict for a v6 probe that must be blocked. Only a timeout can count
    as SECURE, and only when a positive control proves the path would
    otherwise work -- over IPv6 an absent route (ULA without NAT66, no
    upstream v6) also produces a timeout, so without that proof "not
    reachable" is ambiguous. An 'unreachable' outcome is a *local* no-route
    error: the packet never left the container and the firewall was not
    exercised, so it is never SECURE. A successful connection is always a
    firm leak."""
    if outcome == 'connected':
        return INSECURE
    if outcome.startswith('skipped'):
        return SKIPPED
    if outcome == 'timeout':
        return SECURE if positive else INCONCLUSIVE
    return INCONCLUSIVE   # refused, unreachable, error


def _v6_not_reachable_meaning(outcome, control_gap):
    """Explanation for an INCONCLUSIVE v6 block probe, matched to the actual
    cause instead of a one-size-only text."""
    if outcome == 'refused':
        return REFUSED_MEANING
    if outcome == 'unreachable':
        return ('The container has no route to this address: the connection '
                'failed locally and no packet ever left the container, so '
                'the firewall was not exercised.')
    if outcome.startswith('error'):
        return f'The probe failed before any packet was sent ({outcome}).'
    return (f'Not reachable, but {control_gap}, so a real block cannot be '
            'told apart from the container simply having no IPv6 path.')


def baseline_findings_v6(results, env, host, engine):
    """Interpret the IPv6 probes under the "block beyond the host" contract:
    container -> host is blocked like IPv4, and everything past the host (LAN
    and internet alike) is blocked too -- so, unlike IPv4, a reachable v6
    internet target is INSECURE, not OK.

    A blocked v6 probe is only reported SECURE when a positive control shows
    the path would otherwise be usable; otherwise it is INCONCLUSIVE, because
    an unconfigured IPv6 setup blocks the same traffic the firewall would."""
    findings = []

    # v6 availability: host must have a routable v6 address AND the engine must
    # have given the probe container one
    if not host.ipv6:
        findings.append(Finding(
            'v6-skip', 'IPv6 tests', SKIPPED,
            meaning='This host has no routable IPv6 address, so IPv6 '
                    'containment could not be tested.', section=SECTION_V6))
        return findings
    if not env.get('self_ip6'):
        findings.append(Finding(
            'v6-skip', 'IPv6 tests', SKIPPED,
            meaning='The engine did not assign the probe container a routable '
                    'IPv6 address (container IPv6 is off), so there is nothing '
                    'to test. after6.rules still governs any container that '
                    'does get IPv6.', section=SECTION_V6))
        return findings

    def result(fid):
        return results.get(fid, {'outcome': 'skipped: probe not run'})

    # positive controls -------------------------------------------------------
    # container <-> container, or the opened host escape-hatch port, prove the
    # container has working IPv6 on the bridge, i.e. that the container -> host
    # path exists (so a blocked host probe is a real block, not absent
    # connectivity). host-open6 is the stronger control: it is the same path as
    # the blocked host probes, just permitted.
    c2c = result('c2c6')
    host_open6 = result('host-open6')
    bridge_v6 = (c2c['outcome'] == 'connected'
                 or host_open6['outcome'] == 'connected')
    # a globally-routable container address plus a default route means the
    # container is provisioned to reach the IPv6 internet, so a blocked
    # internet probe is a real block.
    try:
        self_global = ipaddress.ip_address(env['self_ip6']).is_global
    except ValueError:
        self_global = False
    internet_capable = self_global and bool(env.get('gateway6'))

    # report the positive control first so the INCONCLUSIVE verdicts below make
    # sense to the reader
    findings.append(Finding(
        'c2c6', f'Container -> container over IPv6 (port {PORT_C2C})',
        verdict_allowed(c2c['outcome']), observed=describe(c2c),
        meaning='Containers can talk to each other over IPv6 (this also '
                'confirms the container has usable IPv6, so the host checks '
                'below are meaningful).'
        if bridge_v6 else
        'Container-to-container IPv6 is blocked; check the "-i docker+ -o '
        'docker+ -j RETURN" rules in after6.rules.'
        if not c2c['outcome'].startswith('skipped') else
        'The listener container has no IPv6 address, so container IPv6 '
        'connectivity could not be confirmed; the host checks below can only '
        'be INCONCLUSIVE.', section=SECTION_V6))

    # escape hatch over IPv6: setup opened this host port, so it must be
    # reachable even though after6.rules otherwise blocks container -> host
    if 'host-open6' in results:
        findings.append(Finding(
            'host-open6',
            f'Container -> host escape-hatch port {PORT_HOST_OPEN} over IPv6 '
            '(opened by setup)',
            verdict_allowed(host_open6['outcome']), observed=describe(host_open6),
            meaning='A host port opened with "ufw allow in on docker+/podman+" '
                    'is reachable from containers over IPv6.'
            if host_open6['outcome'] == 'connected' else
            f'Host port {PORT_HOST_OPEN} is not reachable over IPv6. Either '
            'ufw_setup.sh has not run, or the container has no usable IPv6 '
            'path to the host.',
            actions=[] if host_open6['outcome'] == 'connected' else
            ['Run: sudo tests/ufw_setup.sh'], section=SECTION_V6))

    # container -> host, via the v6 gateway and via the host's own v6 address.
    # The gateway is on-link, so working bridge IPv6 (c2c) is a sufficient
    # positive control for it; the host's own address is a *routed* target,
    # which additionally needs the container to have a default route.
    has_route6 = bool(env.get('gateway6'))
    checks = (
        ('host-gw6', f'its IPv6 gateway {env.get("gateway6")}', bridge_v6,
         'container-to-container IPv6 did not succeed'),
        ('host-lan6', f'host IPv6 address {host.lan_ip6}',
         bridge_v6 and has_route6,
         'container-to-container IPv6 did not succeed' if not bridge_v6 else
         'the container has no IPv6 default route to reach this routed '
         'address'),
    )
    for fid, target, positive, control_gap in checks:
        res = result(fid)
        title = f'Container -> {target} (host test port {PORT_HOST_BLOCKED})'
        if fid == 'host-lan6' and env.get('self_ip6') \
                and env['self_ip6'] == host.lan_ip6:
            findings.append(Finding(
                fid, title, INCONCLUSIVE,
                observed='the probe container itself holds this address',
                meaning='A user-mode network stack copied the host IPv6 '
                        'address into the container, so this probe never '
                        'leaves the container namespace.', section=SECTION_V6))
            continue
        verdict = _v6_block(res['outcome'], positive)
        findings.append(Finding(
            fid, title, verdict, observed=describe(res),
            meaning='Containers cannot reach host services over IPv6.'
            if verdict == SECURE else
            'A container reached a host service over IPv6.'
            if verdict == INSECURE else
            _v6_not_reachable_meaning(res['outcome'], control_gap),
            actions=containment_actions6(engine) if verdict == INSECURE else [],
            section=SECTION_V6))

    # container -> internet over v6: must be blocked (the beyond-host flip).
    # If the host itself cannot reach the IPv6 internet, the container provably
    # cannot either (it routes through the host), so the probe is uninformative
    # and reported as SKIPPED rather than a vague INCONCLUSIVE.
    if host.internet6 is False:
        findings.append(Finding(
            'inet6', f'Container -> internet over IPv6 ({INTERNET_TCP6} tcp)',
            SKIPPED, observed='host has no IPv6 internet route',
            meaning='This host cannot reach the IPv6 internet, so a container '
                    'could not either regardless of the firewall. The '
                    'container->LAN check (cross_host_tests.py) still applies.',
            section=SECTION_V6))
    elif 'inet6' in results:
        res = result('inet6')
        verdict = _v6_block(res['outcome'], internet_capable)
        if res['outcome'] == 'timeout':
            # the probe only runs when the host reaches the IPv6 internet, so
            # a timeout without the container-side control is the actionable
            # "container IPv6 is effectively off" case
            inconclusive_meaning = (
                'Not reachable. The host reaches the IPv6 internet, but this '
                'container has no globally-routable IPv6 address and default '
                'route (e.g. Docker\'s default ULA without NAT66), so it '
                'could not reach the internet regardless of the firewall. '
                'Container IPv6 is effectively off; if you enable routable '
                'container IPv6, re-run to confirm the rules block it.')
        else:
            inconclusive_meaning = _v6_not_reachable_meaning(res['outcome'], '')
        findings.append(Finding(
            'inet6', f'Container -> internet over IPv6 ({INTERNET_TCP6} tcp)',
            verdict, observed=describe(res),
            meaning='Container IPv6 egress beyond the host is blocked, as '
                    'intended.' if verdict == SECURE else
            'Containers have IPv6 connectivity beyond the host; after6.rules '
            'is not installed or not effective.' if verdict == INSECURE else
            inconclusive_meaning,
            actions=containment_actions6(engine) if verdict == INSECURE else [],
            section=SECTION_V6))
    return findings


def containment_actions6(engine):
    if engine.rootless:
        return containment_actions(engine)
    return ['Install the IPv6 rules: sudo cp ufw/after6.rules '
            '/etc/ufw/after6.rules && sudo ufw reload',
            'Inspect the live chains: sudo ip6tables -L DOCKER-USER -v -n']


# --- main --------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('docker', 'podman', 'sudo-podman'),
                        help='podman = rootless (plain podman); '
                             'sudo-podman = rootful podman via sudo')
    parser.add_argument('--no-internet', action='store_true',
                        help=f'do not contact {INTERNET_TCP[0]} / {INTERNET_DNS}')
    parser.add_argument('--json', action='store_true',
                        help='machine-readable findings on stdout')
    parser.add_argument('--rebuild', action='store_true',
                        help='rebuild the probe image even if present')
    return parser.parse_args()


def main():
    args = parse_args()
    require_setup()   # checks ufw_setup.sh has run (backups present, not stale)
    engine = make_engine(choose_engine_name(args))
    engine.rootless = engine_is_rootless(engine)

    findings = []
    if engine.rootless:
        findings.append(Finding(
            'rootless', f'{engine.flavor} is running in rootless mode',
            INFO,
            meaning='Container traffic is relayed by a user-mode network '
                    f'stack and never crosses a {engine.bridge_prefix}+ interface, so after.rules '
                    'cannot confine it (see the "Caveats" section of the '
                    'README). The findings below show what that means in '
                    'practice; the verdict rules are the same as for rootful '
                    'engines.',
            section='Environment'))

    host = HostEnv(probe_internet=not args.no_internet)
    host.print_summary(engine)
    if host.rules_installed is False:
        findings.append(Finding(
            'rules-file', '/etc/ufw/after.rules has no DOCKER-USER section',
            INFO,
            meaning='The rules appear not to be installed; expect INSECURE '
                    'results below.',
            actions=install_actions()[:1], section='Environment'))
    elif host.rules_installed is None:
        findings.append(Finding(
            'rules-file', '/etc/ufw/after.rules is not readable', INFO,
            meaning='Could not verify that the rules are installed; the '
                    'verdicts below are based on observed behavior only.',
            section='Environment'))

    listeners = HostListeners()
    network_created = False
    try:
        # harness self-check: the listeners must be reachable from the host
        if probes.tcp_probe('127.0.0.1', PORT_HOST_BLOCKED) != 'connected':
            sys.exit('harness error: cannot reach own test listener')

        ensure_image(engine, args.rebuild)
        network_created = ensure_test_network(engine)
        listener_ip, listener_ip6 = start_listener_container(engine)

        spec = [
            {'id': 'host-gw', 'kind': 'tcp', 'host': '@gateway',
             'port': PORT_HOST_BLOCKED},
            {'id': 'host-lo', 'kind': 'tcp', 'host': '@gateway',
             'port': PORT_HOST_LOOPBACK},
        ]
        if host.lan_ip:
            spec.append({'id': 'host-lan', 'kind': 'tcp', 'host': host.lan_ip,
                         'port': PORT_HOST_BLOCKED})
        if listener_ip:
            spec.append({'id': 'c2c', 'kind': 'tcp', 'host': listener_ip,
                         'port': PORT_C2C})
        # escape-hatch port opened by ufw_setup.sh: must be reachable
        spec.append({'id': 'host-open', 'kind': 'tcp', 'host': '@gateway',
                     'port': PORT_HOST_OPEN})
        for ip in host.lan_dns:
            spec.append({'id': f'dns-udp-{ip}', 'kind': 'dns_udp', 'host': ip})
            spec.append({'id': f'dns-tcp-{ip}', 'kind': 'dns_tcp', 'host': ip})
        if host.gateway:
            spec.append({'id': 'router-80', 'kind': 'tcp', 'host': host.gateway,
                         'port': 80})
            spec.append({'id': 'router-443', 'kind': 'tcp', 'host': host.gateway,
                         'port': 443})
        # only probe container->internet when the host itself has internet;
        # otherwise baseline_findings reports it SKIPPED
        if not args.no_internet and host.internet4:
            spec.append({'id': 'inet-tcp', 'kind': 'tcp',
                         'host': INTERNET_TCP[0], 'port': INTERNET_TCP[1]})
            spec.append({'id': 'inet-dns', 'kind': 'dns_udp',
                         'host': INTERNET_DNS})

        # IPv6 probes (interpreted by baseline_findings_v6; skipped there when
        # the host or container has no IPv6)
        if host.ipv6:
            spec.append({'id': 'host-gw6', 'kind': 'tcp', 'host': '@gateway6',
                         'port': PORT_HOST_BLOCKED})
            spec.append({'id': 'host-lan6', 'kind': 'tcp', 'host': host.lan_ip6,
                         'port': PORT_HOST_BLOCKED})
            if listener_ip6:
                spec.append({'id': 'c2c6', 'kind': 'tcp', 'host': listener_ip6,
                             'port': PORT_C2C})
            else:
                spec.append({'id': 'c2c6', 'kind': 'tcp', 'host': '::1',
                             'port': PORT_C2C,
                             'skip': 'listener container has no IPv6 address'})
            spec.append({'id': 'host-open6', 'kind': 'tcp', 'host': '@gateway6',
                         'port': PORT_HOST_OPEN})
            # only probe container->internet6 when the host itself has v6
            # internet; otherwise baseline_findings_v6 reports it SKIPPED
            if not args.no_internet and host.internet6:
                ip6, port6 = INTERNET_TCP6.rsplit(':', 1)
                spec.append({'id': 'inet6', 'kind': 'tcp',
                             'host': ip6.strip('[]'), 'port': int(port6)})

        print('Running baseline probes from a container (blocked probes '
              f'take {int(probes.TIMEOUT)}s each to time out)...')
        env, results = run_container_probes(engine, spec)
        findings += baseline_findings(results, env, host, engine)
        findings += baseline_findings_v6(results, env, host, engine)

        findings.append(Finding(
            'cross-host', 'Cross-host tests', SKIPPED,
            meaning='Not part of this run. Whether the engine bypasses UFW '
                    'for inbound traffic can only be observed from another '
                    'machine; run tests/cross_host_tests.py with '
                    'remote_peer.py on a second LAN host.',
            section='Cross-host'))
    except KeyboardInterrupt:
        print('\nInterrupted.')
        findings.append(Finding(
            'interrupted', 'Run interrupted by user', INFO,
            meaning='Later phases did not run; the findings below are '
                    'partial.', section='Environment'))
    finally:
        quiet(engine.cmd('rm', '-f', LISTENER_NAME))
        if network_created:
            remove_test_network(engine)
        listeners.close()

    print()
    if args.json:
        print(report.render_json(findings))
    else:
        print(report.render_text(findings))
    teardown_reminder()
    return report.exit_code(findings)


if __name__ == '__main__':
    sys.exit(main())
