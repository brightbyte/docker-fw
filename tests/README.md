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

On the host under test (with the rules installed and `ufw` enabled):

```bash
python3 tests/host_tests.py
```

Requires Python 3 (stdlib only) and docker or podman. Engine selection:
`--engine docker`, `--engine podman` (plain podman, i.e. rootless), or
`--engine sudo-podman` (rootful podman via sudo); without the flag the script
asks. Engine commands are run via `sudo` only where unavoidable
(`sudo-podman`, or docker without socket access), and firewall changes are
never made by the script — interactive steps print a `sudo ufw` command and
wait for you to run it.

Privileges: the scripts themselves need nothing beyond high-port sockets and
world-readable files — `remote_peer.py` can literally run as `nobody`, and
with `--engine podman` (rootless) `host_tests.py` needs no privileges at all.
For rootful engines, the one hard requirement is the ability to drive the
engine (docker socket access or sudo); that is inherent to testing an engine,
and note that docker-socket access is root-equivalent anyway, so running the
orchestrator as a special unprivileged user gains nothing.

Useful flags: `--engine docker|podman|sudo-podman`, `--no-internet` (do not
contact 1.1.1.1/9.9.9.9), `--no-guided` (skip the interactive ufw steps),
`--json`, `--rebuild` (rebuild the probe image).

## What it does

The suite builds a small probe image (`docker-fw-test`), starts one listener
container (published port 65502, internal port 65503), starts listeners on
the host itself, and then runs probes from a second container:

- container → host services (via bridge gateway IP and LAN IP): must be blocked
- container → loopback-bound host service: must be unreachable
- container → container: must work
- container → DNS on the LAN (auto-detected): must work
- container → LAN gateway: must be blocked
- container → internet (well-known IPs): must work
- guided: `ufw allow in on docker+/podman+ to any port 65504` must open
  exactly that port

Before the first temporary rule, the suite asks you to stash the current ufw
user rules (`/etc/ufw/user.rules{,6}` → `*.fwtest`) and verifies you did: the
stash must exist and match the current rules files in size and mtime (checked
via `stat()` metadata, which needs no root; `cp -a` preserves the mtime, so an
outdated backup of since-changed rules shows up as a mismatch and triggers a
re-prompt). At the end of the run —
also after a crash or Ctrl-C — it prints the restore commands (copy back +
`ufw reload`), waits, and re-verifies that the test ports are blocked again.
If you decline the stash, it falls back to printing individual `ufw delete`
commands instead. The restore clobbers ufw rules added *between* stash and
restore, so don't do unrelated firewall work during a test run.

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

Started without arguments, it prints the `remote_peer.py` invocation to run
on the second machine (including this host's IP for `--allow-from` and the
peer-side ufw command), then asks for the peer's IP — which `remote_peer.py`
prints when it starts. If you already know the peer's IP, pass it directly:
`python3 tests/cross_host_tests.py <peer-ip>`.

This checks: container → LAN peer must be blocked (the peer reports whether
anything arrived), and peer → published port 65502 must be blocked until
explicitly allowed with ufw (guided step, using the same stash/restore flow
as `host_tests.py`). Remove the peer-side ufw rule when done.

The control channel (port 65510) is an unauthenticated LAN test tool; the
peer accepts commands only from `--allow-from` (or the first client to
connect). Don't leave it running.

## Reserved ports

All test traffic uses ports 65500–65511, above the Linux ephemeral range and
unlikely to collide with real services or existing ufw rules:

| Port | Where | Purpose |
|---|---|---|
| 65500 | host, wildcard bind | container → host must be blocked |
| 65501 | host, 127.0.0.1 bind | never reachable from containers |
| 65502 | container, published | inbound-from-LAN test |
| 65503 | container, internal | container → container test |
| 65504 | host, wildcard bind | guided ufw escape-hatch test |
| 65510 | peer | control channel |
| 65511 | peer | container → LAN test |

## Limitations

- IPv4 only, like `after.rules` itself. If your containers have IPv6
  connectivity, it evades both the rules and these tests.
- Verdicts are based on observed behavior; a SECURE verdict means the tested
  path was blocked *now*, on *this* configuration.
- The DNS tests depend on a resolver existing on the LAN or host; the
  internet tests depend on the host actually having internet access.
