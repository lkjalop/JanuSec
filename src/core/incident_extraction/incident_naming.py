"""Generate human-readable incident names from cluster data."""
from __future__ import annotations
from typing import Dict, List, Optional

from .mitre_phase_mapping import technique_to_phase, KILLCHAIN_PHASE_ORDER


_PHASE_LABEL: dict[str, str] = {
    'reconnaissance':       'Recon',
    'resource_development': 'Resource Dev',
    'initial_access':       'Initial Access',
    'execution':            'Execution',
    'persistence':          'Persistence',
    'privilege_escalation': 'Privilege Escalation',
    'defense_evasion':      'Defense Evasion',
    'credential_access':    'Credential Access',
    'discovery':            'Discovery',
    'lateral_movement':     'Lateral Movement',
    'collection':           'Collection',
    'command_and_control':  'C2',
    'exfiltration':         'Exfiltration',
    'impact':               'Impact',
}

_SOURCE_SHORT: dict[str, str] = {
    'azure': 'Azure',
    'entra': 'Entra',
    'okta':  'Okta',
    'mimecast': 'Email',
    'proofpoint': 'Email',
    'sailpoint': 'IdM',
    'endpoint': 'Endpoint',
    'network': 'Network',
    'firewall': 'Firewall',
    'siem': 'SIEM',
}


def generate_incident_name(
    rows: List[dict],
    entities: Dict[str, List[str]],
    index: int = 1,
    severity: str = 'medium',
    what_happened: Optional[str] = None,
) -> str:
    """Return a concise, analyst-friendly incident name.

    Priority: what_happened prefix → phase span + actor + source
    """
    if what_happened:
        short = what_happened.split('.')[0].strip()
        if 10 < len(short) <= 80:
            return f'[{severity.upper()}] {short}'

    actor = _primary_actor(entities)
    phase_label = _phase_label_for_rows(rows)
    source_label = _source_label(rows)

    parts = [phase_label]
    if actor:
        parts.append(f'by {actor}')
    if source_label:
        parts.append(f'via {source_label}')
    name = ' '.join(parts) or f'Incident {index}'
    return f'[{severity.upper()}] {name}'


def _primary_actor(entities: Dict[str, List[str]]) -> Optional[str]:
    for field in ('user_principal_name', 'username', 'accounts', 'account_id'):
        vals = entities.get(field) or []
        if vals:
            v = str(vals[0])
            if '@' in v:
                return v.split('@')[0]
            return v[:30]
    return None


def _phase_label_for_rows(rows: List[dict]) -> str:
    phases: set[str] = set()
    for row in rows:
        techs = row.get('mitre') or ([row['mitre_technique']] if row.get('mitre_technique') else [])
        for t in techs:
            p = technique_to_phase(str(t))
            if p != 'unknown':
                phases.add(p)
    ordered = [_PHASE_LABEL.get(p, p) for p in KILLCHAIN_PHASE_ORDER if p in phases]
    if not ordered:
        return 'Unknown Activity'
    if len(ordered) == 1:
        return ordered[0]
    return f'{ordered[0]} → {ordered[-1]}'


def _source_label(rows: List[dict]) -> str:
    sources: set[str] = set()
    for row in rows:
        src = (row.get('source_sheet') or row.get('source_file') or row.get('source_type') or '').lower()
        for key, label in _SOURCE_SHORT.items():
            if key in src:
                sources.add(label)
                break
    if not sources:
        return ''
    return '/'.join(sorted(sources)[:2])
