#!/bin/sh
# Show packets blocked by the docker-fw rules, from the kernel log, one line
# per packet with only the fields needed to tell what was blocked.
# Arguments are passed on to journalctl, e.g.:
#   ./log.sh --since "1 hour ago"
#   ./log.sh -f
#   ./log.sh -b         (current boot only)
# The rules log at most 3 packets per minute (bursts of up to 10), so this
# shows a sample of the blocked traffic, not all of it.
set -eu

journalctl _TRANSPORT=kernel -o short-iso --grep 'UFW DOCKER BLOCK' "$@" | awk '
/UFW DOCKER BLOCK/ {
    line = $1
    for (i = 2; i <= NF; i++)
        if ($i ~ /^(IN|OUT|SRC|DST|PROTO|SPT|DPT)=/)
            line = line " " $i
    print line
    fflush()
    next
}
{ print; fflush() }
'
