"""Detect kill-chain phase progression and parallel chains within a cluster."""
from __future__ import annotations
from typing import Dict, List, Tuple

from .mitre_phase_mapping import technique_to_phase, KILLCHAIN_PHASE_ORDER


def detect_kill_chain_phases(rows: List[dict]) -> List[str]:
    """Return ordered list of kill-chain phases present in rows."""
    seen: set[str] = set()
    ordered: list[str] = []
    for phase in KILLCHAIN_PHASE_ORDER:
        for row in rows:
            if phase in seen:
                break
            techs = _row_techniques(row)
            if any(technique_to_phase(t) == phase for t in techs):
                seen.add(phase)
                ordered.append(phase)
    return ordered


def detect_parallel_chains(rows: List[dict]) -> List[List[str]]:
    """Return candidate parallel kill-chain threads by user principal.

    Each thread is a list of phases attributed to one principal.
    Returns empty list when no split is evident.
    """
    by_principal: dict[str, set[str]] = {}
    for row in rows:
        principal = (
            row.get('user_principal_name')
            or row.get('username')
            or row.get('account_id')
            or '__unknown__'
        )
        phases = {technique_to_phase(t) for t in _row_techniques(row) if technique_to_phase(t) != 'unknown'}
        if phases:
            by_principal.setdefault(principal, set()).update(phases)

    if len(by_principal) < 2:
        return []

    # Two principals have disjoint phase sets → strong parallel chain signal
    principals = list(by_principal.keys())
    chains: list[list[str]] = []
    for p in principals:
        thread = _ordered_phases(by_principal[p])
        if thread:
            chains.append(thread)
    return chains if len(chains) >= 2 else []


def phase_span(rows: List[dict]) -> Tuple[str, str]:
    """Return (earliest_phase, latest_phase) in kill-chain order for rows."""
    phases = set()
    for row in rows:
        for t in _row_techniques(row):
            p = technique_to_phase(t)
            if p != 'unknown':
                phases.add(p)
    ordered = _ordered_phases(phases)
    if not ordered:
        return ('unknown', 'unknown')
    return (ordered[0], ordered[-1])


def _row_techniques(row: dict) -> List[str]:
    techs = row.get('mitre') or []
    if not techs and row.get('mitre_technique'):
        techs = [row['mitre_technique']]
    return [str(t) for t in techs if t]


def _ordered_phases(phases: set) -> List[str]:
    return [p for p in KILLCHAIN_PHASE_ORDER if p in phases]
