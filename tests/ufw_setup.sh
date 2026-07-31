#!/bin/sh
# Prepare a host for the docker-fw test suite: back up the live ufw rules and
# open the two ports the test runners expect to be reachable. Run once, as
# root, before host_tests.py / cross_host_tests.py. Undo with ufw_teardown.sh.
#
# Everything this does is a literal command below; read it before running.
set -eu

# Ports the runners treat as "must be reachable" escape hatches. The matching
# check in the runners lives in tests/fwtest/ufw.py; keep these in sync.
HOST_PORT=65504        # container -> host
PUBLISHED_PORT=65505   # published port (LAN -> container); also the peer's
                       # egress-probe control target
# Peer ports (used when this machine is the cross-host peer). Harmless on a
# container host, where nothing listens on them. See fwtest/protocol.py.
CONTROL_PORT=65510     # remote_peer.py control channel
PEER_PROBE_PORT=65511  # remote_peer.py egress-probe listener

RULES=/etc/ufw/user.rules
RULES6=/etc/ufw/user6.rules
BACKUP=/etc/ufw/user.rules.fwtest
BACKUP6=/etc/ufw/user6.rules.fwtest

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root, e.g.: sudo tests/ufw_setup.sh" >&2
    exit 1
fi

# Back up the current rules once, as the clean-state reference for teardown.
# If a backup already exists, keep it (do not capture an already-modified
# state); run ufw_teardown.sh first if you want a fresh snapshot.
if [ -e "$BACKUP" ]; then
    echo "backup already present; keeping it as the clean-state reference"
else
    cp "$RULES" "$BACKUP"
    chmod 600 "$BACKUP"
    if [ -e "$RULES6" ]; then
        cp "$RULES6" "$BACKUP6"
        chmod 600 "$BACKUP6"
    fi
    echo "backed up the current ufw rules"
fi

# Open the escape-hatch ports. All bridge prefixes the rules recognise, so the
# same setup covers docker and podman, the default bridge (docker+/podman+) and
# the suite's dedicated network (br-* for docker, matched by br+). ufw applies
# each portspec to IPv4 and IPv6. These are idempotent: re-adding is a no-op.
ufw allow in on docker+ to any port "$HOST_PORT"
ufw allow in on podman+ to any port "$HOST_PORT"
ufw allow in on br+ to any port "$HOST_PORT"
ufw route allow proto tcp from any to any port "$PUBLISHED_PORT"

# Peer role: open the control channel and the egress-probe targets so this
# machine can serve as the cross-host peer. These are plain INPUT allows (the
# route rule above does not cover traffic to the peer's own listeners). Opened
# to any for both address families; remote_peer.py's --allow-from remains the
# access control for the control channel, so keep using it.
ufw allow "$CONTROL_PORT"/tcp
ufw allow "$PEER_PROBE_PORT"/tcp
ufw allow "$PUBLISHED_PORT"/tcp

echo
echo "opened container-host ports $HOST_PORT/$PUBLISHED_PORT and peer ports"
echo "$CONTROL_PORT/$PEER_PROBE_PORT/$PUBLISHED_PORT. run tests/ufw_teardown.sh when done."
