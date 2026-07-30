#!/usr/bin/env python3
"""Probe a running system for the security outcomes promised by
ufw/after.rules (see the top-level README) and report verdicts.

Run unprivileged on the host under test:

    python3 tests/host_tests.py [--engine docker|podman|sudo-podman]
                                [--no-internet] [--no-guided] [--json]

Inbound exposure to the LAN cannot be tested from the host itself; that is
a separate script, tests/cross_host_tests.py, run against a second machine.

--engine podman is plain (rootless) podman; --engine sudo-podman is the
rootful engine. All engines are probed with the same tests and judged by
the same verdict rules; only the explanations and hints differ.

The script never changes firewall state itself; steps that need root are
printed as copy-paste sudo commands with interactive confirmation.
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

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE = 'docker-fw-test'
LISTENER_NAME = 'fwtest-listener'

PORT_HOST_BLOCKED = 65500   # host listener, wildcard bind: must be unreachable
PORT_HOST_LOOPBACK = 65501  # host listener, 127.0.0.1 bind: must be unreachable
PORT_PUBLISHED = 65502      # published by container A: LAN-inbound test
PORT_C2C = 65503            # container A internal: container-to-container test
PORT_GUIDED = 65504         # host listener: ufw escape-hatch test
PORT_PEER_CONTROL = 65510   # remote_peer.py control channel
PORT_PEER_PROBE = 65511     # remote peer listener: container-to-LAN test

INTERNET_TCP = ('1.1.1.1', 443)
INTERNET_DNS = '9.9.9.9'

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
    def __init__(self):
        self.gateway, self.lan_iface = self._default_route()
        self.lan_ip = self._lan_ip()
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
        print(f'  LAN interface:   {self.lan_iface}, IP {self.lan_ip}')
        print(f'  default gateway: {self.gateway}')
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
    BINDS = [('0.0.0.0', PORT_HOST_BLOCKED),
             ('127.0.0.1', PORT_HOST_LOOPBACK),
             ('0.0.0.0', PORT_GUIDED)]

    def __init__(self):
        self.servers = []
        for addr, port in self.BINDS:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind((addr, port))
            except OSError as e:
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


def start_listener_container(engine):
    quiet(engine.cmd('rm', '-f', LISTENER_NAME))
    spec = json.dumps({'tcp_ports': [PORT_PUBLISHED, PORT_C2C]})
    run(engine.cmd('run', '-d', '--rm', '--name', LISTENER_NAME,
                   '-p', f'{PORT_PUBLISHED}:{PORT_PUBLISHED}',
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
    ip = settings.get('IPAddress')
    if not ip:
        ip = next((n['IPAddress'] for n in settings.get('Networks', {}).values()
                   if n.get('IPAddress')), None)
    return ip


def run_container_probes(engine, spec):
    """Run container_probe.py in a throwaway container; return (env, results-by-id)."""
    p = run(engine.cmd('run', '--rm', IMAGE, 'probe', json.dumps(spec)),
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
        verdict = verdict_blocked(res['outcome'], refused_means_reached=True)
        actions = []
        if verdict == INSECURE:
            actions = containment_actions(engine)
            if engine.rootless:
                actions = ['Note: with pasta --map-gw, gateway-addressed '
                           'traffic is redirected to the host itself; the '
                           'response may come from the host, not the '
                           'router.'] + actions
        else:
            actions = ['To deliberately allow LAN access for containers, add '
                       'explicit ACCEPT rules to the DOCKER-USER section']
        findings.append(Finding(
            fid, f'Container -> LAN gateway {host.gateway} (port {port})',
            verdict, observed=describe(res),
            meaning='Containers cannot reach other machines on the LAN.'
            if verdict == SECURE else
            'Container traffic reached a network stack at the LAN gateway '
            'address; code running in containers can leave its confinement.'
            if verdict == INSECURE else '',
            actions=actions))

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
            'Containers appear to have no internet access. If this host is '
            f'offline that is expected; otherwise check the "-i {engine.bridge_prefix}+ -j RETURN" '
            'rules in DOCKER-USER.'))

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


# --- phase 2: guided ufw escape hatch ---------------------------------------

def prompt_step(text):
    print()
    print(text)
    return input('Press Enter when done (or "s" to skip): ').strip().lower() != 's'


class UfwStash:
    """Temporary ufw rules the user is asked to add, and the stash of
    /etc/ufw/user.rules taken before the first one so everything can be
    restored in one step at the end of the run."""

    STASH_CMDS = ('sudo cp -a /etc/ufw/user.rules /etc/ufw/user.rules.fwtest\n'
                  '    sudo cp -a /etc/ufw/user6.rules /etc/ufw/user6.rules.fwtest')
    RESTORE_CMDS = ('sudo cp -a /etc/ufw/user.rules.fwtest /etc/ufw/user.rules\n'
                    '    sudo cp -a /etc/ufw/user6.rules.fwtest /etc/ufw/user6.rules\n'
                    '    sudo ufw reload\n'
                    '    sudo rm /etc/ufw/user.rules.fwtest /etc/ufw/user6.rules.fwtest')

    FILES = ('/etc/ufw/user.rules', '/etc/ufw/user6.rules')
    SUFFIX = '.fwtest'

    def __init__(self):
        self.offered = False
        self.stashed = False
        self.delete_cmds = []   # fallback if the user declined the stash

    def check(self, prompted_at):
        """Verify the stash via stat() metadata (the files are not readable
        without root, but /etc/ufw is searchable): each stash file must
        exist and match its original in size and mtime (cp -a preserves the
        mtime, so a faithful copy of the *current* file matches exactly; an
        outdated backup of since-changed rules shows up as a mismatch). A
        stash that matches but predates the prompt (ctime) is accepted with
        a note: it is identical to the current rules, so it is a valid
        restore point even though this run did not create it.

        Returns (problems, notes): problems mean the stash is not usable;
        notes are informational."""
        problems, notes = [], []
        for orig in self.FILES:
            stash = orig + self.SUFFIX
            try:
                orig_stat = os.stat(orig)
            except FileNotFoundError:
                continue  # nothing to stash for this file
            except OSError as e:
                notes.append(f'cannot verify {orig}: {e}')
                continue
            try:
                stash_stat = os.stat(stash)
            except FileNotFoundError:
                problems.append(f'{stash} does not exist')
                continue
            except OSError as e:
                notes.append(f'cannot verify {stash}: {e}')
                continue
            if stash_stat.st_size != orig_stat.st_size \
                    or stash_stat.st_mtime_ns != orig_stat.st_mtime_ns:
                problems.append(
                    f'{stash} differs from {orig} in size or mtime. If you just copied '
                    'it, use cp -a. But if this stash is from an earlier '
                    'test run whose restore was skipped, it is your clean '
                    'restore point: restore it instead of overwriting it '
                    '(check for leftover test rules first: sudo ufw show '
                    'added | grep 655).')
            elif stash_stat.st_ctime < prompted_at:
                notes.append(f'{stash} already existed and matches the current '
                             'rules; using it as the restore point.')
        return problems, notes

    def ensure(self):
        """Offer the stash once, before the first temporary rule is added,
        and verify the user actually took it."""
        if self.offered:
            return
        self.offered = True
        text = ('Before adding temporary rules, stash the current ufw user '
                'rules so everything can be restored in one step at the end '
                '(a skipped stash means individual delete commands later):'
                f'\n\n    {self.STASH_CMDS}')
        while True:
            prompted_at = time.time()
            if not prompt_step(text):
                self.stashed = False
                return
            problems, notes = self.check(prompted_at)
            for note in notes:
                print(f'NOTE: {note}')
            if not problems:
                if not notes:
                    print('Stash verified: it exists and matches the '
                          'current rules files.')
                self.stashed = True
                return
            print('The stash does not check out:')
            for problem in problems:
                print(f'  - {problem}')
            text = f'Please run the stash commands:\n\n    {self.STASH_CMDS}'

    def note(self, delete_cmd):
        self.delete_cmds.append(delete_cmd)


def guided_phase(engine, args, findings, stash):
    section = 'Guided (temporary ufw rules)'
    if args.no_guided or not sys.stdin.isatty():
        findings.append(Finding(
            'guided', f'ufw escape-hatch test (port {PORT_GUIDED})', SKIPPED,
            meaning='Skipped ({}). Run interactively without --no-guided to '
                    'verify that the documented "ufw allow in on {}+" escape '
                    'hatch works.'.format('--no-guided' if args.no_guided else 'no tty',
                       engine.bridge_prefix),
            section=section))
        return
    prefix = engine.bridge_prefix
    allow_cmd = f'sudo ufw allow in on {prefix}+ to any port {PORT_GUIDED}'

    # pre-check: the demonstration only means something if the port starts
    # out blocked
    print(f'Checking that port {PORT_GUIDED} starts out blocked...')
    _, results = run_container_probes(engine, [
        {'id': 'pre', 'kind': 'tcp', 'host': '@gateway', 'port': PORT_GUIDED},
    ])
    pre_open = results['pre']['outcome'] == 'connected'
    if pre_open:
        findings.append(Finding(
            'guided-pre',
            f'Container -> host port {PORT_GUIDED} before any allow rule',
            INSECURE, observed=describe(results['pre']),
            meaning='The escape-hatch port is reachable before any ufw allow '
                    'rule was added (this matches the container->host '
                    'findings above).',
            actions=containment_actions(engine), section=section))

    stash.ensure()
    if not prompt_step('This step verifies the documented escape hatch. '
                       f'In another terminal, run:\n\n    {allow_cmd}'):
        findings.append(Finding('guided', 'ufw escape-hatch test', SKIPPED,
                                meaning='Skipped by user.', section=section))
        return
    stash.note(f'sudo ufw delete allow in on {prefix}+ to any port {PORT_GUIDED}')
    _, results = run_container_probes(engine, [
        {'id': 'allowed', 'kind': 'tcp', 'host': '@gateway', 'port': PORT_GUIDED},
        {'id': 'other', 'kind': 'tcp', 'host': '@gateway', 'port': PORT_HOST_BLOCKED},
    ])
    outcome = results['allowed']['outcome']
    if pre_open:
        findings.append(Finding(
            'guided-allowed',
            f'Container -> host port {PORT_GUIDED} with allow rule active',
            INCONCLUSIVE,
            observed=describe(results['allowed']),
            meaning='The port was already reachable before the rule was '
                    'added, so this result cannot show whether the ufw '
                    'escape hatch has any effect.',
            section=section))
    else:
        findings.append(Finding(
            'guided-allowed',
            f'Container -> host port {PORT_GUIDED} with allow rule active',
            verdict_allowed(outcome),
            observed=describe(results['allowed']),
            meaning='The documented escape hatch works: single host ports '
                    'can be opened to containers with ufw.'
            if outcome == 'connected' else
            'The allow rule had no effect. Check that your bridge interfaces '
            'actually match the "{}+" prefix (ip -o link).{}'.format(prefix,
               f' Rootless engine traffic does not use {prefix}+ interfaces at all, '
               'so interface-scoped ufw rules can never match it.'
               if engine.rootless else ''),
            section=section))
    outcome = results['other']['outcome']
    findings.append(Finding(
        'guided-other',
        f'Container -> host port {PORT_HOST_BLOCKED} with allow rule active',
        verdict_blocked(outcome, refused_means_reached=False),
        observed=outcome,
        meaning='Other host ports stay blocked while one is allowed.'
        if outcome == 'timeout' else
        f'The allow rule opened more than port {PORT_GUIDED}!'
        if outcome == 'connected' else '',
        section=section))

    # rule removal happens once, for all phases, in restore_phase()


# --- phase 3: cross-host -----------------------------------------------------

# --- restore -----------------------------------------------------------------

def ack_restore(text):
    """Like prompt_step, but safe to call from a finally block: a closed
    stdin or another Ctrl-C must not abort the cleanup instructions."""
    print()
    print(text)
    try:
        return input('Press Enter when done (or "s" to skip): ') \
            .strip().lower() != 's'
    except (EOFError, KeyboardInterrupt):
        print('\n(not waiting; run the commands above when convenient)')
        return False


def restore_announce(findings, stash, interrupted):
    """Print the restore (or fallback delete) commands for temporary ufw
    rules. Returns True when the user confirmed running them. Shared with
    cross_host_tests.py.

    After an interrupt, only print the commands -- blocking on input right
    after a Ctrl-C would look like a hang."""
    section = 'Cleanup'
    if not stash.delete_cmds:
        return False
    if interrupted:
        if stash.stashed:
            what, cmds = 'Restore the stashed state', stash.RESTORE_CMDS
        else:
            what, cmds = 'Remove them', '\n    '.join(stash.delete_cmds)
        print()
        print(f'Temporary ufw rules may still be active. {what}:\n\n    {cmds}')
        findings.append(Finding(
            'cleanup', 'Removal of temporary ufw rules', INCONCLUSIVE,
            observed='run interrupted; commands printed but not verified',
            meaning='Run the printed commands to remove the temporary test '
                    'rules, then check: sudo ufw status numbered',
            actions=[cmds.replace('\n    ', ' && ')], section=section))
        return False
    if stash.stashed:
        done = ack_restore('The run asked you to add temporary ufw rules. '
                           f'Restore the stashed state:\n\n    {stash.RESTORE_CMDS}')
    else:
        done = ack_restore('The run asked you to add temporary ufw rules and '
                           'no stash was taken. Remove them:\n\n    {}'.format('\n    '.join(stash.delete_cmds)))
    if not done:
        findings.append(Finding(
            'cleanup', 'Removal of temporary ufw rules', INCONCLUSIVE,
            observed='restore step skipped',
            meaning='Temporary test rules may still be active on this '
                    'system.',
            actions=([stash.RESTORE_CMDS] if stash.stashed
                     else stash.delete_cmds), section=section))
    return done


def restore_phase(engine, findings, stash, interrupted=False):
    """Runs in a finally block: announce the restore, then re-verify that
    the guided escape-hatch port is blocked again."""
    section = 'Cleanup'
    if not restore_announce(findings, stash, interrupted):
        return

    # the guided port must be blocked again
    try:
        _, results = run_container_probes(engine, [
            {'id': 'closed', 'kind': 'tcp', 'host': '@gateway',
             'port': PORT_GUIDED},
        ])
        res = results['closed']
        findings.append(Finding(
            'cleanup-host',
            f'Container -> host port {PORT_GUIDED} after restore',
            SECURE if res['outcome'] != 'connected' else INSECURE,
            observed=describe(res),
            meaning='Restore verified; the port is blocked again.'
            if res['outcome'] != 'connected' else
            'The port is still reachable; a test rule appears to still be '
            'active. Check: sudo ufw status numbered',
            section=section))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as e:
        findings.append(Finding(
            'cleanup-host',
            f'Container -> host port {PORT_GUIDED} after restore',
            INCONCLUSIVE, observed=f'verification failed: {e}',
            meaning='Could not re-probe after the restore; check manually: '
                    'sudo ufw status numbered', section=section))


# --- main --------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('docker', 'podman', 'sudo-podman'),
                        help='podman = rootless (plain podman); '
                             'sudo-podman = rootful podman via sudo')
    parser.add_argument('--no-internet', action='store_true',
                        help=f'do not contact {INTERNET_TCP[0]} / {INTERNET_DNS}')
    parser.add_argument('--no-guided', action='store_true',
                        help='skip interactive steps that ask for sudo ufw commands')
    parser.add_argument('--json', action='store_true',
                        help='machine-readable findings on stdout')
    parser.add_argument('--rebuild', action='store_true',
                        help='rebuild the probe image even if present')
    return parser.parse_args()


def main():
    args = parse_args()
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

    host = HostEnv()
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
    stash = UfwStash()
    interrupted = False
    try:
        # harness self-check: the listeners must be reachable from the host
        if probes.tcp_probe('127.0.0.1', PORT_HOST_BLOCKED) != 'connected':
            sys.exit('harness error: cannot reach own test listener')

        ensure_image(engine, args.rebuild)
        listener_ip = start_listener_container(engine)

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
        for ip in host.lan_dns:
            spec.append({'id': f'dns-udp-{ip}', 'kind': 'dns_udp', 'host': ip})
            spec.append({'id': f'dns-tcp-{ip}', 'kind': 'dns_tcp', 'host': ip})
        if host.gateway:
            spec.append({'id': 'router-80', 'kind': 'tcp', 'host': host.gateway,
                         'port': 80})
            spec.append({'id': 'router-443', 'kind': 'tcp', 'host': host.gateway,
                         'port': 443})
        if not args.no_internet:
            spec.append({'id': 'inet-tcp', 'kind': 'tcp',
                         'host': INTERNET_TCP[0], 'port': INTERNET_TCP[1]})
            spec.append({'id': 'inet-dns', 'kind': 'dns_udp',
                         'host': INTERNET_DNS})

        print('Running baseline probes from a container (blocked probes '
              f'take {int(probes.TIMEOUT)}s each to time out)...')
        env, results = run_container_probes(engine, spec)
        findings += baseline_findings(results, env, host, engine)

        guided_phase(engine, args, findings, stash)
        findings.append(Finding(
            'cross-host', 'Cross-host tests', SKIPPED,
            meaning='Not part of this run. Whether the engine bypasses UFW '
                    'for inbound traffic can only be observed from another '
                    'machine; run tests/cross_host_tests.py with '
                    'remote_peer.py on a second LAN host.',
            section='Cross-host'))
    except KeyboardInterrupt:
        interrupted = True
        print('\nInterrupted.')
        findings.append(Finding(
            'interrupted', 'Run interrupted by user', INFO,
            meaning='Later phases did not run; the findings below are '
                    'partial.', section='Environment'))
    finally:
        try:
            # needs the host listeners and the listener container still up
            restore_phase(engine, findings, stash, interrupted)
        except KeyboardInterrupt:
            print('\nInterrupted again; any outstanding cleanup commands '
                  'were printed above.')
        finally:
            quiet(engine.cmd('rm', '-f', LISTENER_NAME))
            listeners.close()

    print()
    if args.json:
        print(report.render_json(findings))
    else:
        print(report.render_text(findings))
    return report.exit_code(findings)


if __name__ == '__main__':
    sys.exit(main())
