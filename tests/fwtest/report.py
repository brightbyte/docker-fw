"""Verdict model and report rendering.

Verdicts describe the security posture, not test pass/fail:
  SECURE       - an attack path is blocked as intended
  INSECURE     - an attack path is open
  OK           - an intentionally allowed path works
  RESTRICTED   - an intentionally allowed path is blocked (functionality
                 problem, not a security problem)
  INCONCLUSIVE - the observation does not support a verdict
  SKIPPED      - the test did not run (missing prerequisite)
  INFO         - informational, no expectation attached
"""

import json
import sys

SECURE = 'SECURE'
INSECURE = 'INSECURE'
OK = 'OK'
RESTRICTED = 'RESTRICTED'
INCONCLUSIVE = 'INCONCLUSIVE'
SKIPPED = 'SKIPPED'
INFO = 'INFO'

_COLORS = {
    SECURE: '32',
    OK: '32',
    INSECURE: '1;31',
    RESTRICTED: '33',
    INCONCLUSIVE: '35',
    SKIPPED: '36',
    INFO: '36',
}


class Finding:
    def __init__(self, fid, title, verdict, observed='', meaning='',
                 actions=None, section='Baseline'):
        self.fid = fid
        self.title = title
        self.verdict = verdict
        self.observed = observed
        self.meaning = meaning
        self.actions = actions or []
        self.section = section

    def as_dict(self):
        return {
            'id': self.fid,
            'section': self.section,
            'title': self.title,
            'verdict': self.verdict,
            'observed': self.observed,
            'meaning': self.meaning,
            'actions': self.actions,
        }


def _tag(verdict, color):
    if color:
        return '\033[{}m[{}]\033[0m'.format(_COLORS.get(verdict, '0'), verdict)
    return f'[{verdict}]'


def render_text(findings, color=None):
    if color is None:
        color = sys.stdout.isatty()
    lines = []
    section = None
    for f in findings:
        if f.section != section:
            section = f.section
            lines += ['', f'=== {section} ===', '']
        lines.append(f'{_tag(f.verdict, color)} {f.title}')
        if f.observed:
            lines.append(f'    observed: {f.observed}')
        if f.meaning:
            lines.append(f'    {f.meaning}')
        for action in f.actions:
            lines.append(f'    -> {action}')
        lines.append('')

    counts = {}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    summary = ', '.join(f'{n} {v}' for v, n in sorted(counts.items()))
    lines += ['=== Summary ===', '', summary]
    if counts.get(INSECURE):
        lines.append(_tag(INSECURE, color) +
                     ' At least one containment property does NOT hold on this system.')
    else:
        lines.append(_tag(SECURE, color) +
                     ' No open attack paths were observed.')
    return '\n'.join(lines)


def render_json(findings):
    return json.dumps([f.as_dict() for f in findings], indent=2)


def exit_code(findings):
    return 1 if any(f.verdict == INSECURE for f in findings) else 0
