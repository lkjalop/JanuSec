"""
SABSA business-consequence mapper.

Deterministic: maps evidence patterns to SABSA trust attributes then builds a
2-3 line coda template. This is the INPUT to the LLM render prompt, not the
final styled output — the render prompt styles it.
"""
from __future__ import annotations

import re

# Maps evidence signal keywords → breached SABSA attribute name
_SABSA_IMPACT_MAP: list[tuple[list[str], str]] = [
    (['rclone', 'backblaze', 'mega', 'azcopy', 'gsutil', 'exfil', 'copy into', 'unload'],
     'Confidential'),
    (['lsass', 'comsvcs', 'mimikatz', 'credential', 'password spray', 'mfa fatigue'],
     'Authenticated'),
    (['c2', 'beacon', 'dns tunnel', 'command-and-control', 'cobalt'],
     'Monitored'),
    (['lateral', 'psexec', 'wmiexec', 'rdp', 'smb'],
     'Authorised'),
    (['bec', 'inbox rule', 'wire', 'finance'],
     'Reputable'),
    (['unconstrained', 'no dlp', 'no pam', 'no gate', 'without baseline'],
     'Authorised'),
]


def derive_breached_attributes(fragments: dict[str, str | None]) -> list[str]:
    """
    Deterministic SABSA attribute mapping from combined fragment text.
    Returns a de-duplicated ordered list of breached attributes.
    """
    combined = ' '.join(str(v or '') for v in fragments.values()).lower()
    seen: set[str] = set()
    out: list[str] = []
    for keywords, attribute in _SABSA_IMPACT_MAP:
        if attribute not in seen and any(kw in combined for kw in keywords):
            seen.add(attribute)
            out.append(attribute)
    return out


def build_sabsa_coda(
    fragments: dict[str, str | None],
    breached_attributes: list[str] | None = None,
) -> str:
    """
    Template-based 2-3 sentence business-consequence paragraph.

    This is the DRAFT passed to the LLM render prompt — not the final output.
    The render prompt styles it; it must not add facts beyond these sentences.
    """
    if breached_attributes is None:
        breached_attributes = derive_breached_attributes(fragments)

    if not breached_attributes:
        return ''

    attrs_str = ' and '.join(breached_attributes)
    lines: list[str] = [f'Business consequence. {attrs_str} integrity is degraded.']

    # Control gap hint: first clause of exploitability fragment before the period
    expl = fragments.get('exploitability') or ''
    if expl:
        gap_hint = expl.rstrip('.').split('.')[0].replace('Control gaps exploited: ', '')
        lines.append(f'The evidence exposes a control gap: {gap_hint}.')

    # MTTD note: only if greater than 7 days (worth calling out)
    disc = fragments.get('discoverability') or ''
    m = re.search(r'(\d+)-day MTTD', disc)
    if m:
        days = int(m.group(1))
        if days > 7:
            lines.append(
                f'The {days}-day detection window indicates monitoring controls '
                f'did not correlate this activity until cross-source analysis ran.'
            )

    return ' '.join(lines)
