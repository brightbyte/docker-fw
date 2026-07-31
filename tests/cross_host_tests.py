#!/usr/bin/env python3
"""Cross-host tests: observe from a second LAN machine whether the container
engine bypasses UFW. Independent of host_tests.py; run unprivileged on the
host under test:

    sudo tests/ufw_setup.sh         # once, before testing
    python3 tests/cross_host_tests.py [PEER-IP] [--engine docker|podman|sudo-podman]
                                      [--json] [--rebuild]
    sudo tests/ufw_teardown.sh      # once, when done

Without PEER-IP, the script prints the remote_peer.py invocation to run on
the other host (including this host's IP) and then asks for the peer's IP,
which remote_peer.py prints when it starts. The peer helper also prints the
ufw command to open its firewall for the control channel.

Tests: container -> other LAN host must be blocked (the peer reports whether
anything arrived); the LAN peer must not reach the unopened published port
but must reach the one ufw_setup.sh opened with `ufw route allow`.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_tests
from host_tests import (
    Finding, SECURE, INSECURE, INCONCLUSIVE, INFO, OK, RESTRICTED,
    PORT_PUBLISHED, LISTENER_NAME,
    containment_actions, quiet,
)
from fwtest import probes, report
from fwtest.protocol import CONTROL_PORT, PORT_PEER_PROBE, PeerControl
from fwtest.ufw import PORT_PUBLISHED_OPEN, require_setup, teardown_reminder

SECTION = 'Cross-host'


def setup_actions(host):
    # the peer needs remote_peer.py running and the test ports open in its ufw;
    # ufw_setup.sh opens the peer ports too, so the same script serves here
    return [
        f'On the peer: python3 tests/remote_peer.py --allow-from {host.lan_ip}',
        'On the peer: sudo tests/ufw_setup.sh   (opens the peer test ports; '
        'undo with ufw_teardown.sh)',
    ]


def engine_manages_ipv6(engine):
    """Best-effort: does the engine forward/publish container IPv6 at the
    firewall level? A '::' host binding on a published port means it does
    (docker: ip6tables enabled). Returns True/False, or None if undetermined.
    For podman this is weaker evidence -- netavark manages its own chains and
    may not bind '::' or route through DOCKER-USER -- so the egress verdict
    relies on the differential control below, not on this."""
    p = host_tests.run(engine.cmd('inspect', LISTENER_NAME),
                       capture=True, check=False, echo=False)
    try:
        ports = json.loads(p.stdout)[0]['NetworkSettings']['Ports'] or {}
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    for bindings in ports.values():
        for binding in bindings or []:
            if binding.get('HostIp') in ('::', '::0'):
                return True
    return False


def egress_test(engine, peer, peer_ip, peer_ip6, host, findings):
    """container -> other LAN host must be blocked. The peer also listens on
    the route-allowed port (PORT_PUBLISHED_OPEN): container egress to it is a
    positive control proving egress WOULD work when permitted, so a blocked
    result on PORT_PEER_PROBE is a real block, not absent connectivity."""
    peer.call(cmd='reset')
    peer.call(cmd='listen', port=PORT_PEER_PROBE)
    peer.call(cmd='listen', port=PORT_PUBLISHED_OPEN)
    _egress_one(engine, peer, peer_ip, host, findings, family='4')
    if host.ipv6 and peer_ip6:
        _egress_one(engine, peer, peer_ip6, host, findings, family='6')


def _egress_one(engine, peer, target, host, findings, family):
    suffix = '' if family == '4' else ' over IPv6'
    fid = 'peer-egress' if family == '4' else 'peer-egress6'
    title = f'Container -> other LAN host{suffix} (port {PORT_PEER_PROBE})'
    # sanity: this host must itself reach the peer on both ports, otherwise the
    # peer-side firewall is interfering and neither result would mean anything
    unreachable = [p for p in (PORT_PEER_PROBE, PORT_PUBLISHED_OPEN)
                   if probes.tcp_probe(target, p) != 'connected']
    if unreachable:
        findings.append(Finding(
            fid, title, INCONCLUSIVE,
            observed=f'host cannot reach peer port(s) {unreachable}',
            meaning='This host cannot reach the peer on these ports, so the '
                    'container probes would prove nothing. Open them on the '
                    'peer\'s ufw for this host'
                    + (' (including this host\'s IPv6 address).'
                       if family == '6' else '.'),
            actions=setup_actions(host), section=SECTION))
        return

    def arrivals(port):
        return len(peer.call(cmd='connections', port=port)['connections'])

    peer.call(cmd='reset')
    before_ctrl, before_test = arrivals(PORT_PUBLISHED_OPEN), arrivals(PORT_PEER_PROBE)
    _, results = host_tests.run_container_probes(engine, [
        {'id': 'ctrl', 'kind': 'tcp', 'host': target,
         'port': PORT_PUBLISHED_OPEN},
        {'id': 'test', 'kind': 'tcp', 'host': target, 'port': PORT_PEER_PROBE},
    ])
    egress_works = (results['ctrl']['outcome'] == 'connected'
                    or arrivals(PORT_PUBLISHED_OPEN) > before_ctrl)
    reached = (results['test']['outcome'] == 'connected'
               or arrivals(PORT_PEER_PROBE) > before_test)

    if reached:
        findings.append(Finding(
            fid, title, INSECURE,
            observed=f"reached the peer ({results['test']['outcome']})",
            meaning='Container traffic reached another machine on the LAN.',
            actions=containment_actions(engine), section=SECTION))
    elif not egress_works:
        detail = ''
        if family == '6' and engine_manages_ipv6(engine) is False:
            detail = (' The engine does not appear to forward container IPv6 '
                      '(for docker, set "ip6tables": true in daemon.json; '
                      'podman/netavark manages its own chains).')
        findings.append(Finding(
            fid, title, INCONCLUSIVE,
            observed=f"blocked, but the route-allowed control port was also "
                     f"unreached ({results['ctrl']['outcome']})",
            meaning='The container could not reach the peer even on the '
                    'route-allowed port, so it has no working '
                    + ('IPv6 ' if family == '6' else '')
                    + 'egress path to test the block against; a blocked result '
                    'cannot be told apart from absent connectivity.' + detail,
            actions=[], section=SECTION))
    else:
        findings.append(Finding(
            fid, title, SECURE,
            observed=f"blocked ({results['test']['outcome']}); egress on the "
                     "route-allowed port works",
            meaning='Containers cannot reach other machines on the LAN. Egress '
                    'on the route-allowed port confirms the container could '
                    'otherwise reach the peer, so this is a real block.',
            actions=[], section=SECTION))


def inbound_test(engine, peer, host, findings):
    """LAN peer -> published container ports. The unopened port must be
    blocked by UFW; the port ufw_setup.sh opened with `ufw route allow` must
    be reachable. No rule is toggled during the run."""
    for family, host_ip in (('4', host.lan_ip),
                            ('6', host.lan_ip6 if host.ipv6 else None)):
        if not host_ip:
            continue
        _inbound_blocked(peer, host_ip, engine, findings, family)
        _inbound_open(peer, host_ip, findings, family)


def _inbound_blocked(peer, host_ip, engine, findings, family):
    suffix = '' if family == '4' else ' over IPv6'
    fid = 'peer-inbound' if family == '4' else 'peer-inbound6'
    outcome = peer.call(cmd='probe', host=host_ip, port=PORT_PUBLISHED)['outcome']
    findings.append(Finding(
        fid, f'LAN peer -> unopened published port {PORT_PUBLISHED}{suffix}',
        INSECURE if outcome == 'connected' else SECURE,
        observed=outcome,
        meaning='The container engine published this port past UFW; every '
                'published port on this host is open to the network.'
        if outcome == 'connected' else
        'Published container ports are subject to UFW like any host service '
        '(this port has no route rule, and is blocked).',
        actions=containment_actions(engine) if outcome == 'connected' else [],
        section=SECTION))


def _inbound_open(peer, host_ip, findings, family):
    suffix = '' if family == '4' else ' over IPv6'
    fid = 'peer-inbound-open' if family == '4' else 'peer-inbound-open6'
    outcome = peer.call(cmd='probe', host=host_ip,
                        port=PORT_PUBLISHED_OPEN)['outcome']
    findings.append(Finding(
        fid, f'LAN peer -> route-opened published port {PORT_PUBLISHED_OPEN}'
        f'{suffix} (opened by setup)',
        OK if outcome == 'connected' else RESTRICTED,
        observed=outcome,
        meaning='A published port opened with "ufw route allow" is reachable '
                'from the LAN, as intended: the escape hatch works.'
        if outcome == 'connected' else
        f'Published port {PORT_PUBLISHED_OPEN} is not reachable even though '
        'setup opened it. Either ufw_setup.sh has not run, or (if only IPv6 '
        'fails) the engine did not publish the port on IPv6.',
        actions=[] if outcome == 'connected' else
        ['Run: sudo tests/ufw_setup.sh',
         'Verify the rule with: sudo ufw show added'],
        section=SECTION))


def print_peer_instructions(host):
    print()
    print('On the other host, start the helper:')
    print()
    print(f'    python3 tests/remote_peer.py --allow-from {host.lan_ip}')
    print()
    print()
    print('If UFW is active there, open the test ports (same script as on the '
          'host):')
    print()
    print('    sudo tests/ufw_setup.sh')
    print()
    print("remote_peer.py prints the peer's IP address when it starts.")


def prompt_for_peer(host):
    """Print the peer-side setup instructions and ask for the peer's IP."""
    if not sys.stdin.isatty():
        sys.exit('no PEER-IP given and no tty to ask on; pass the peer\'s '
                 'IP as an argument')
    print()
    print('No peer given.')
    print_peer_instructions(host)
    while True:
        peer = input("Enter the peer's IP address: ").strip()
        if peer:
            return peer


def connect_peer(peer_ip, host, findings):
    """Connect to the peer's control channel. On failure, print the setup
    instructions and offer to retry (same or corrected IP). Returns
    (PeerControl or None, final peer IP)."""
    while True:
        try:
            peer = PeerControl(peer_ip)
            peer.call(cmd='hello')
            return peer, peer_ip
        except (OSError, RuntimeError) as e:
            print()
            print(f'Could not connect to the peer at {peer_ip}:{CONTROL_PORT}: {e}')
            if not sys.stdin.isatty():
                give_up = True
            else:
                print("Either remote_peer.py is not running there, or the "
                      "peer's firewall blocks the control channel.")
                print_peer_instructions(host)
                answer = input(f"Enter the peer's IP address (Enter to retry "
                               f"{peer_ip}, 'q' to give up): ").strip()
                give_up = answer.lower() == 'q'
                if answer and not give_up:
                    peer_ip = answer
            if give_up:
                findings.append(Finding(
                    'peer-control',
                    f'Control connection to remote peer {peer_ip}:{CONTROL_PORT}',
                    INCONCLUSIVE, observed=str(e),
                    meaning='Could not talk to remote_peer.py; no cross-host '
                            'test was run.',
                    actions=setup_actions(host), section=SECTION))
                return None, peer_ip


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('peer', metavar='PEER-IP', nargs='?',
                        help='IP of the second LAN host running '
                             'remote_peer.py; omit to be shown setup '
                             'instructions and prompted for it')
    parser.add_argument('--engine', choices=('docker', 'podman', 'sudo-podman'),
                        help='podman = rootless (plain podman); '
                             'sudo-podman = rootful podman via sudo')
    parser.add_argument('--json', action='store_true',
                        help='machine-readable findings on stdout')
    parser.add_argument('--rebuild', action='store_true',
                        help='rebuild the probe image even if present')
    return parser.parse_args()


def main():
    args = parse_args()
    require_setup()   # checks ufw_setup.sh has run (backups present, not stale)
    engine = host_tests.make_engine(host_tests.choose_engine_name(args))
    engine.rootless = host_tests.engine_is_rootless(engine)

    findings = []
    if engine.rootless:
        findings.append(Finding(
            'rootless', f'{engine.flavor} is running in rootless mode', INFO,
            meaning='after.rules cannot confine rootless engines (see the '
                    '"Caveats" section of the README); expect the container '
                    '-> LAN test to come out INSECURE. Inbound behavior is '
                    'still meaningful: rootless published ports are bound on '
                    'the host and governed by UFW.',
            section='Environment'))

    host = host_tests.HostEnv()
    host.print_summary(engine)
    if not host.lan_ip:
        sys.exit('could not determine this host\'s LAN IP')
    if not args.peer:
        args.peer = prompt_for_peer(host)

    network_created = False
    try:
        host_tests.ensure_image(engine, args.rebuild)
        network_created = host_tests.ensure_test_network(engine)
        host_tests.start_listener_container(engine)

        # args.peer is updated to whichever IP actually connected
        peer, args.peer = connect_peer(args.peer, host, findings)
        if peer:
            try:
                peer_ip6 = peer.call(cmd='hello').get('ip6')
                egress_test(engine, peer, args.peer, peer_ip6, host, findings)
                inbound_test(engine, peer, host, findings)
            except (OSError, RuntimeError) as e:
                findings.append(Finding(
                    'peer-error', 'Communication with the remote peer',
                    INCONCLUSIVE, observed=str(e),
                    meaning='The peer reported an error or the control '
                            'channel dropped mid-test; results are partial. '
                            'If the peer says a port is already in use, a '
                            'stale remote_peer.py may be running there '
                            '(restart it).',
                    actions=setup_actions(host), section=SECTION))
            finally:
                peer.close()
    except KeyboardInterrupt:
        print('\nInterrupted.')
        findings.append(Finding(
            'interrupted', 'Run interrupted by user', INFO,
            meaning='Later tests did not run; the findings below are '
                    'partial.', section='Environment'))
    finally:
        quiet(engine.cmd('rm', '-f', LISTENER_NAME))
        if network_created:
            host_tests.remove_test_network(engine)

    print()
    if args.json:
        print(report.render_json(findings))
    else:
        print(report.render_text(findings))
    teardown_reminder()
    return report.exit_code(findings)


if __name__ == '__main__':
    sys.exit(main())
