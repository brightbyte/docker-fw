#!/bin/sh
# Undo ufw_setup.sh: restore the ufw rules from the backup it made. If the
# backup is gone, delete the test rules directly. Run once, as root.
#
# Everything this does is a literal command below; read it before running.
set -eu

HOST_PORT=65504
PUBLISHED_PORT=65505
CONTROL_PORT=65510
PEER_PROBE_PORT=65511
RULES=/etc/ufw/user.rules
RULES6=/etc/ufw/user6.rules
BACKUP=/etc/ufw/user.rules.fwtest
BACKUP6=/etc/ufw/user6.rules.fwtest

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root, e.g.: sudo tests/ufw_teardown.sh" >&2
    exit 1
fi

if [ -e "$BACKUP" ]; then
    # restore the pre-test rules and reload
    cp "$BACKUP" "$RULES"
    if [ -e "$BACKUP6" ]; then
        cp "$BACKUP6" "$RULES6"
    fi
    ufw reload
    rm -f "$BACKUP" "$BACKUP6"
    echo "restored the ufw rules from the backup and removed it"
else
    # no backup: delete the rules ufw_setup.sh adds (|| true: ignore if absent)
    echo "no backup found; deleting the known test rules directly"
    ufw delete allow in on docker+ to any port "$HOST_PORT" || true
    ufw delete allow in on podman+ to any port "$HOST_PORT" || true
    ufw delete allow in on br+ to any port "$HOST_PORT" || true
    ufw route delete allow proto tcp from any to any port "$PUBLISHED_PORT" || true
    ufw delete allow "$CONTROL_PORT"/tcp || true
    ufw delete allow "$PEER_PROBE_PORT"/tcp || true
    ufw delete allow "$PUBLISHED_PORT"/tcp || true
    echo "done (best-effort). verify with: sudo ufw show added"
fi
