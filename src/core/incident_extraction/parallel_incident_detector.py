"""Detect whether a cluster contains parallel, simultaneous incidents."""
from __future__ import annotations
from typing import List, Tuple

from .kill_chain_phase_detector import detect_parallel_chains, _row_techniques
from .mitre_phase_mapping import technique_to_phase


_EARLY_PHASES = frozenset({'reconnaissance', 'resource_development', 'initial_access'})
_LATE_PHASES = frozenset({'exfiltration', 'impact', 'command_and_control'})


def detect_parallel_incidents(rows: List[dict]) -> Tuple[bool, str]:
    """Return (is_parallel, rationale) for a cluster of rows.

    True when evidence strongly suggests two simultaneous independent attack chains.
    """
    chains = detect_parallel_chains(rows)
    if len(chains) >= 2:
        chain_strs = [' → '.join(c) for c in chains[:2]]
        rationale = f'Two principal threads detected: [{chain_strs[0]}] vs [{chain_strs[1]}]'
        return True, rationale

    # Fallback: check if early and late phases co-occur in disjoint source types
    by_source: dict[str, set[str]] = {}
    for row in rows:
        src = row.get('source_sheet') or row.get('source_file') or row.get('source_type') or '__unknown__'
        phases = {technique_to_phase(t) for t in _row_techniques(row) if technique_to_phase(t) != 'unknown'}
        by_source.setdefault(src, set()).update(phases)

    sources = list(by_source.keys())
    if len(sources) < 2:
        return False, 'single source type — no parallel split'

    for i, s1 in enumerate(sources):
        for s2 in sources[i + 1:]:
            p1, p2 = by_source[s1], by_source[s2]
            if (p1 & _EARLY_PHASES and p2 & _LATE_PHASES and not (p1 & p2)):
                rationale = f'Source {s1} covers early phases; {s2} covers late phases with no overlap'
                return True, rationale
            if (p2 & _EARLY_PHASES and p1 & _LATE_PHASES and not (p1 & p2)):
                rationale = f'Source {s2} covers early phases; {s1} covers late phases with no overlap'
                return True, rationale

    return False, 'phases form one continuous chain'
