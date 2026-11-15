#!/bin/sh
# Install ufw/after.rules and ufw/after6.rules into /etc/ufw and reload UFW.
# The previous rules are kept as numbered backups next to them
# (after.backup, after.backup.~1~, ...). Run as root.
set -eu

cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root, e.g.: sudo ./install.sh" >&2
    exit 1
fi

cp --backup=numbered /etc/ufw/after.rules /etc/ufw/after.backup
cp ufw/after.rules /etc/ufw/after.rules
cp --backup=numbered /etc/ufw/after6.rules /etc/ufw/after6.backup
cp ufw/after6.rules /etc/ufw/after6.rules
ufw reload
echo "to revert: sudo sh -c 'cp /etc/ufw/after.backup /etc/ufw/after.rules && cp /etc/ufw/after6.backup /etc/ufw/after6.rules && ufw reload'"
