"""Runner-side helpers for the UFW test fixture.

The firewall setup/teardown is done by the shell scripts tests/ufw_setup.sh
and tests/ufw_teardown.sh -- kept as plain, literal shell so a security-
conscious developer can audit them before running as root. This module is the
unprivileged half the test runners use: the port numbers they probe, and the
check that the setup has been run.

The port numbers and backup paths below MUST match tests/ufw_setup.sh.
"""

import os
import sys
import time

# Ports ufw_setup.sh opens; the runners probe these expecting them reachable.
PORT_HOST_OPEN = 65504        # container -> host escape hatch
PORT_PUBLISHED_OPEN = 65505   # published port opened with `ufw route allow`

# Backups ufw_setup.sh writes. Their presence/age is the "setup has run"
# marker the runners check (stat only, so no privileges are needed).
BACKUP = ('/etc/ufw/user.rules.fwtest', '/etc/ufw/user6.rules.fwtest')

# A backup older than this is treated as probably stale.
STALE_AGE = 6 * 3600


def check_setup():
    """Return ('ok'|'stale'|'missing', age_seconds_or_None) from the backup
    files' timestamps."""
    mtimes = []
    for backup in BACKUP:
        try:
            mtimes.append(os.path.getmtime(backup))
        except OSError:
            pass
    if not mtimes:
        return 'missing', None
    age = time.time() - max(mtimes)
    return ('stale' if age > STALE_AGE else 'ok'), age


def require_setup():
    """Warn (and, on a tty, prompt for confirmation) when the ufw test setup
    is missing or looks stale. Exits if the user declines, or if there is no
    tty to ask on."""
    status, age = check_setup()
    if status == 'ok':
        return
    if status == 'missing':
        print('WARNING: the ufw test setup has not been run (no backup at '
              f'{BACKUP[0]}).', file=sys.stderr)
        print('The "assumed open" port checks will fail until you run:\n'
              '    sudo tests/ufw_setup.sh', file=sys.stderr)
    else:
        print(f'WARNING: the ufw test setup backup is {age / 3600:.1f}h old '
              f'(> {STALE_AGE // 3600}h) and may be stale.', file=sys.stderr)
        print('Check the current rules with:  sudo ufw show added',
              file=sys.stderr)
    if not sys.stdin.isatty():
        sys.exit('Not running: run tests/ufw_setup.sh first, or run '
                 'interactively to override.')
    if input('Continue anyway? [y/N] ').strip().lower() != 'y':
        sys.exit('Aborted; run tests/ufw_setup.sh first.')


def teardown_reminder():
    """Remind the user to restore the firewall, but only if setup left a
    backup in place. Goes to stderr so it does not corrupt --json output."""
    if check_setup()[0] != 'missing':
        print('\nReminder: the test ports are still open. Restore the '
              'firewall when done:\n    sudo tests/ufw_teardown.sh',
              file=sys.stderr)
