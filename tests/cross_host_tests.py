#!/usr/bin/env python3
"""Cross-host tests: observe from a second LAN machine whether the container
engine bypasses UFW. Independent of host_tests.py; run unprivileged on the
host under test:

    python3 tests/cross_host_tests.py [PEER-IP] [--engine docker|podman|sudo-podman]
                                      [--no-guided] [--json] [--rebuild]

Without PEER-IP, the script prints the remote_peer.py invocation to run on
the other host (including this host's IP) and then asks for the peer's IP,
which remote_peer.py prints when it starts. The peer helper also prints the
ufw command to open its firewall for the control channel.

Tests: container -> other LAN host must be blocked (the peer reports whether
anything arrived), and LAN peer -> published container port must be blocked
until explicitly allowed with ufw (guided step, with the same stash/restore
flow as host_tests.py).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_tests
from host_tests import (
    Finding, SECURE, INSECURE, INCONCLUSIVE, INFO,
    PORT_PUBLISHED, PORT_PEER_PROBE, LISTENER_NAME, UfwStash,
    containment_actions, prompt_step, quiet, verdict_allowed,
)
from fwtest import probes, report
from fwtest.protocol import CONTROL_PORT, PeerControl

SECTION = 'Cross-host'


def setup_actions(host):
    return [
        f'On the peer: python3 tests/remote_peer.py --allow-from {host.lan_ip}',
        f'On the peer: sudo ufw allow from {host.lan_ip} to any port '
        f'{CONTROL_PORT},{PORT_PEER_PROBE} proto tcp',
    ]


def egress_test(engine, peer, peer_ip, host, findings):
    """container -> other LAN host: must be blocked."""
    peer.call(cmd='reset')
    peer.call(cmd='listen', port=PORT_PEER_PROBE)
    # sanity: the host itself must be able to reach the peer's test port,
    # otherwise a blocked container probe would prove nothing
    sanity = probes.tcp_probe(peer_ip, PORT_PEER_PROBE)
    if sanity != 'connected':
        findings.append(Finding(
            'peer-egress',
            f'Container -> other LAN host (port {PORT_PEER_PROBE})',
            INCONCLUSIVE,
            observed=f'host itself: {sanity}',
            meaning='This host cannot reach the peer test port, so a blocked '
                    'container probe would prove nothing. The peer-side '
                    'firewall probably interferes.',
            actions=setup_actions(host)[1:2], section=SECTION))
        return
    before = len(peer.call(cmd='connections',
                           port=PORT_PEER_PROBE)['connections'])
    _, results = host_tests.run_container_probes(engine, [
        {'id': 'peer', 'kind': 'tcp', 'host': peer_ip,
         'port': PORT_PEER_PROBE},
    ])
    outcome = results['peer']['outcome']
    after = len(peer.call(cmd='connections',
                          port=PORT_PEER_PROBE)['connections'])
    reached = outcome == 'connected' or after > before
    findings.append(Finding(
        'peer-egress', f'Container -> other LAN host (port {PORT_PEER_PROBE})',
        INSECURE if reached else
        SECURE if outcome == 'timeout' else INCONCLUSIVE,
        observed=f'{outcome}; peer saw {after - before} new connection(s)',
        meaning='Container traffic reached another machine on the LAN.'
        if reached else
        'Containers cannot reach other machines on the LAN.',
        actions=containment_actions(engine) if reached else [],
        section=SECTION))


def inbound_test(engine, peer, host, findings):
    """LAN peer -> published container port: must be blocked by UFW.
    Returns the probe outcome."""
    outcome = peer.call(cmd='probe', host=host.lan_ip,
                        port=PORT_PUBLISHED)['outcome']
    findings.append(Finding(
        'peer-inbound',
        f'LAN peer -> published container port {PORT_PUBLISHED}',
        INSECURE if outcome == 'connected' else SECURE,
        observed=outcome,
        meaning='The container engine published this port past UFW; every '
                'published port on this host is open to the network.'
        if outcome == 'connected' else
        'Published container ports are subject to UFW like any host service.',
        actions=containment_actions(engine) if outcome == 'connected' else
        [f'To expose a published port: sudo ufw allow {PORT_PUBLISHED}/tcp'],
        section=SECTION))
    return outcome


def guided_flip(peer, host, findings, stash):
    """Verify that a published port can be opened deliberately with ufw."""
    allow_cmd = (f'sudo ufw route allow proto tcp from any to any '
                 f'port {PORT_PUBLISHED}')
    stash.ensure()
    if not prompt_step('This step verifies that a published port can be '
                       'opened with ufw. A published port is reached by '
                       'forwarded traffic, so it needs a route rule (not '
                       'plain "ufw allow", which only affects the host '
                       f'itself). In another terminal, run:\n\n    {allow_cmd}'):
        return
    stash.note(f'sudo ufw route delete allow proto tcp from any to any '
               f'port {PORT_PUBLISHED}')
    outcome = peer.call(cmd='probe', host=host.lan_ip,
                        port=PORT_PUBLISHED)['outcome']
    findings.append(Finding(
        'peer-inbound-allowed',
        f'LAN peer -> published port {PORT_PUBLISHED} with allow rule active',
        verdict_allowed(outcome), observed=outcome,
        meaning='A published container port can be opened to the LAN with a '
                'ufw route rule, as intended.'
        if outcome == 'connected' else
        'The route rule did not open the forwarded path. Check that the '
        'DOCKER-USER chain jumps to ufw-user-forward (sudo iptables -L '
        'DOCKER-USER -n) and that the rule was added.',
        section=SECTION))
    # rule removal happens in restore()


def restore(peer_ip, host, findings, stash, interrupted):
    """Announce the restore, then re-verify from the peer that the
    published port is blocked again."""
    if not host_tests.restore_announce(findings, stash, interrupted):
        return
    try:
        peer = PeerControl(peer_ip)
        peer.call(cmd='hello')
        outcome = peer.call(cmd='probe', host=host.lan_ip,
                            port=PORT_PUBLISHED)['outcome']
        peer.close()
        findings.append(Finding(
            'cleanup-peer',
            f'LAN peer -> published port {PORT_PUBLISHED} after restore',
            SECURE if outcome != 'connected' else INSECURE,
            observed=outcome,
            meaning='Restore verified; the published port is blocked again.'
            if outcome != 'connected' else
            'The published port is still open; a test rule appears to still '
            'be active. Check: sudo ufw status numbered',
            section='Cleanup'))
    except (OSError, RuntimeError) as e:
        findings.append(Finding(
            'cleanup-peer',
            f'LAN peer -> published port {PORT_PUBLISHED} after restore',
            INCONCLUSIVE, observed=str(e),
            meaning='Could not re-probe from the peer after the restore; '
                    'check manually: sudo ufw status numbered',
            section='Cleanup'))


def print_peer_instructions(host):
    print()
    print('On the other host, start the helper:')
    print()
    print(f'    python3 tests/remote_peer.py --allow-from {host.lan_ip}')
    print()
    print('If UFW is active there, also allow this host in:')
    print()
    print(f'    sudo ufw allow from {host.lan_ip} to any port '
          f'{CONTROL_PORT},{PORT_PEER_PROBE} proto tcp')
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
    parser.add_argument('--no-guided', action='store_true',
                        help='skip interactive steps that ask for sudo ufw commands')
    parser.add_argument('--json', action='store_true',
                        help='machine-readable findings on stdout')
    parser.add_argument('--rebuild', action='store_true',
                        help='rebuild the probe image even if present')
    return parser.parse_args()


def main():
    args = parse_args()
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

    stash = UfwStash()
    interrupted = False
    try:
        host_tests.ensure_image(engine, args.rebuild)
        host_tests.start_listener_container(engine)

        # args.peer is updated so the restore step reconnects to the IP
        # that actually worked
        peer, args.peer = connect_peer(args.peer, host, findings)
        if peer:
            try:
                egress_test(engine, peer, args.peer, host, findings)
                outcome = inbound_test(engine, peer, host, findings)
                if outcome != 'connected' and not args.no_guided \
                        and sys.stdin.isatty():
                    guided_flip(peer, host, findings, stash)
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
        interrupted = True
        print('\nInterrupted.')
        findings.append(Finding(
            'interrupted', 'Run interrupted by user', INFO,
            meaning='Later tests did not run; the findings below are '
                    'partial.', section='Environment'))
    finally:
        try:
            # needs the listener container still up for re-verification
            restore(args.peer, host, findings, stash, interrupted)
        except KeyboardInterrupt:
            print('\nInterrupted again; any outstanding cleanup commands '
                  'were printed above.')
        finally:
            quiet(engine.cmd('rm', '-f', LISTENER_NAME))

    print()
    if args.json:
        print(report.render_json(findings))
    else:
        print(report.render_text(findings))
    return report.exit_code(findings)


if __name__ == '__main__':
    sys.exit(main())
