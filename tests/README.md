**DICLAIMER**: The security tests are **EXPERIMENTAL** and **BEST EFFORT**.
They heavily rely on AI help for generating test code.
The test suite has been checked experimentally but not strictly verified.
It is supplied in the hope it will be useful, but **WITHOUT ANY WARANTY**
that the verdicts are accurate! Also, the tests change system configuration
and may make the host under test **LESS SECURE** until configuration
is restored. This effect should be minimal, but mistakes can happen.

# Test suite

Probes a running system for the security outcomes promised by
`ufw/after.rules` and reports **security verdicts, not pass/fail**:

| Verdict | Meaning |
|---|---|
| `SECURE` | an attack path is blocked as intended |
| `INSECURE` | an attack path is open |
| `OK` | an intentionally allowed path works |
| `RESTRICTED` | an allowed path is blocked — a functionality problem, not a security problem |
| `INCONCLUSIVE` | the observation does not support a verdict |
| `SKIPPED` | missing prerequisite (e.g. no second host) |
| `INFO` | informational |

Every non-trivial verdict comes with an explanation and suggested actions,
including how to *deliberately* relax the restriction when that is what you
want. The exit code is 1 if anything is INSECURE, 0 otherwise.

## Quick start

Run the one-time setup (backs up the live ufw rules and opens the ports the
tests expect to be reachable), then the runners, then teardown:

```bash
sudo tests/ufw_setup.sh      # once, before testing
python3 tests/host_tests.py
sudo tests/ufw_teardown.sh   # once, when done
```

`ufw_setup.sh` / `ufw_teardown.sh` are the only scripts that change firewall
state, and they run once, not per test. The runners themselves never touch
ufw; at startup they check the setup has run (the backup files exist and are
under 6 hours old) and warn + prompt if not, pointing you at `sudo ufw show
added` to inspect the current state. Setup is safely re-runnable (it keeps the
first backup as the clean-state reference); run teardown before setup if you
want a fresh snapshot.

Requires Python 3 (stdlib only) and docker or podman. Engine selection:
`--engine docker`, `--engine podman` (plain podman, i.e. rootless), or
`--engine sudo-podman` (rootful podman via sudo); without the flag the script
asks. Engine commands are run via `sudo` only where unavoidable
(`sudo-podman`, or docker without socket access).

Privileges: `ufw_setup.sh` / `ufw_teardown.sh` need root (run with `sudo`, or
as a user with sudo — individual commands escalate). The runners need nothing
beyond high-port sockets and world-readable files: `remote_peer.py` can run as
`nobody`, and with `--engine podman` (rootless) `host_tests.py` needs no
privileges at all. For rootful engines the one hard requirement is driving the
engine (docker socket access or sudo), inherent to testing an engine.

Useful flags: `--engine docker|podman|sudo-podman`, `--no-internet` (do not
contact 1.1.1.1/9.9.9.9), `--json`, `--rebuild` (rebuild the probe image).

## What it does

The suite builds a small probe image (`docker-fw-test`), creates a dedicated
dual-stack network (`fwtest-net`, so containers get an IPv6 address and the
IPv6 tests can run — the default bridge has no IPv6 unless the daemon is
configured for it), starts one listener container (published ports 65502 and
65505, internal port 65503), starts listeners on the host itself, and then runs
probes from a second container:

- container → host services (via bridge gateway IP and LAN IP): must be blocked
- container → loopback-bound host service: must be unreachable
- container → host escape-hatch port 65504 (opened by setup with
  `ufw allow in on docker+/podman+`): must be reachable
- container → container: must work
- container → DNS on the LAN (auto-detected): must work
- container → LAN gateway: must be blocked
- container → internet (well-known IPs): must work

Rather than open and close a rule mid-run, setup opens port 65504 (and, for the
cross-host tests, route-opens 65505) once; the runners probe those "assumed
open" ports expecting them reachable, alongside the neighbouring "assumed
closed" ports (65500, 65502) expecting them blocked. If an assumed-open port
comes back blocked, the finding is RESTRICTED and points you at
`ufw_setup.sh`.

The same probes and the same verdict rules apply to every engine, rootless
or rootful — the same observed behavior always yields the same verdict. On
rootless engines (`--engine podman`, or rootless docker) expect INSECURE
findings, since `after.rules` cannot confine user-mode network stacks (see
the "Caveats" section of the top-level README); the findings' hints name the
mechanism behind each result (e.g. pasta's `--map-gw` gateway-to-loopback
mapping). Probes identify what actually answered: test listeners send a
recognizable banner, and the probe container reports its own address (pasta
copies the host's IP into the container, which would otherwise make the
host-LAN-IP probe loop back inside the container unnoticed).

## Cross-host tests

Whether the engine bypasses UFW for *inbound* traffic can only be observed
from another machine — traffic from the host itself takes a different
firewall path. These tests are a separate script, `cross_host_tests.py`,
runnable independently of `host_tests.py`. On the host under test:

```bash
python3 tests/cross_host_tests.py
```

Run `ufw_setup.sh` on the host first, as usual. On the **peer**, run
`remote_peer.py` and, if it has UFW active, `sudo tests/ufw_setup.sh` as well —
the same setup script opens the peer's test ports (65505/65510/65511) in
addition to the container-host escape hatches, so one script serves both roles
(the extra ports it opens on each machine are harmless). Started without
arguments, `cross_host_tests.py` prints the `remote_peer.py` invocation for the
peer (with this host's IP for `--allow-from`) and then asks for the peer's IP,
which `remote_peer.py` prints when it starts. If you already know the peer's
IP, pass it directly: `python3 tests/cross_host_tests.py <peer-ip>`.

This checks: container → LAN peer must be blocked (the peer reports whether
anything arrived); the LAN peer must not reach the unopened published port
65502, but must reach port 65505, which setup opened with `ufw route allow`.

Both checks run over IPv4 and IPv6 when the host and the peer each have a
routable IPv6 address (the peer reports its addresses over the control
channel). The egress check is a **differential**: the peer also listens on the
route-allowed port 65505, and the container probes both it (a positive control
proving egress works when permitted) and the blocked port 65511. A leak on the
blocked port is INSECURE; blocked-while-the-control-works is a firm SECURE;
neither reachable is INCONCLUSIVE (the container has no working egress path, so
a block can't be told apart from absent connectivity) rather than a false
SECURE. For that reason the peer must have ports 65505/65510/65511 open (both
address families), which is exactly what running `ufw_setup.sh` on the peer
does.

Whether the IPv6 egress can be tested at all depends on the engine forwarding
container IPv6. For docker that means `ip6tables: true`; the suite detects it
best-effort (a `::` binding on a published port) and names it in the
INCONCLUSIVE explanation. For podman there is no equivalent flag — netavark
manages its own chains and may not route through `DOCKER-USER` — so the egress
verdict there relies on the observed differential, not on introspection.

The control channel (port 65510) is an unauthenticated LAN test tool; the
peer accepts commands only from `--allow-from` (or the first client to
connect). Don't leave it running.

## Reserved ports

All test traffic uses ports 65500–65511, above the Linux ephemeral range and
unlikely to collide with real services or existing ufw rules. "opened by setup"
ports are opened once by `ufw_setup.sh`; the rest are never opened:

| Port | Where | Purpose |
|---|---|---|
| 65500 | host, wildcard bind | container → host must be blocked |
| 65501 | host, 127.0.0.1 bind | never reachable from containers |
| 65502 | container, published | inbound-from-LAN: must be blocked |
| 65503 | container, internal | container → container test |
| 65504 | host, wildcard bind | container → host escape hatch (opened by setup) |
| 65505 | container, published | inbound-from-LAN: reachable (route opened by setup) |
| 65510 | peer | control channel |
| 65511 | peer | container → LAN test |

## Limitations

- Dual-stack: the suite runs the same probes over IPv4 and IPv6, grouped as
  "Baseline (IPv4)" / "Baseline (IPv6)". The IPv6 section auto-skips (with a
  reason) when the host has no routable IPv6 address or the engine gives
  containers none. Per `after6.rules`, container IPv6 *beyond the host* — LAN
  and internet alike — is expected to be blocked, so a reachable IPv6 internet
  probe is INSECURE, not OK; container-to-host IPv6 behaves like IPv4.
- Over IPv6, a *blocked* result is only reported SECURE when the suite can
  confirm the path would otherwise work (container-to-container IPv6 for the
  on-link gateway check, plus a container default route for the routed host
  address; a globally-routable container address plus the host reaching the
  IPv6 internet for the internet check). Without that confirmation the result
  is INCONCLUSIVE, because an unconfigured IPv6 setup (e.g. Docker's default
  ULA without NAT66) blocks the same traffic the firewall would. A leak (a
  successful connection) is always reported INSECURE.
- Verdicts are based on observed behavior; a SECURE verdict means the tested
  path was blocked *now*, on *this* configuration.
- The DNS tests depend on a resolver existing on the LAN or host; the
  internet tests depend on the host actually having internet access.
