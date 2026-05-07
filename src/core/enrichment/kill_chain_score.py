"""Kill chain completeness scoring.

Maps MITRE ATT&CK techniques observed in a cluster to Lockheed Martin /
Unified Kill Chain phases and computes:

  kill_chain_phases_observed  — list of phase names seen
  kill_chain_completeness     — 0.0 – 1.0 fraction of phases covered
  kill_chain_gaps             — phases NOT observed (attacker may still be here)
  kill_chain_stage_label      — human label: Early / Mid / Late / Full-Cycle
  kill_chain_phase_count      — integer count of distinct phases

A high completeness score means the attacker has executed a multi-phase
campaign and had prolonged access — this significantly boosts verdict
confidence and is surfaced in the exec summary as a "Full-Cycle attack" label.

Usage::
    from src.core.enrichment.kill_chain_score import score_cluster_kill_chain
    score_cluster_kill_chain(cluster, rows)   # mutates cluster in-place
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Phase ordering (Unified Kill Chain + MITRE enterprise) ───────────────────
# 9 phases; reaching phase 7+ is severe.
PHASES: list[str] = [
    'reconnaissance',       # 0
    'initial_access',       # 1
    'execution',            # 2
    'persistence',          # 3
    'privilege_escalation', # 4
    'lateral_movement',     # 5
    'collection',           # 6
    'exfiltration',         # 7
    'impact',               # 8
]

# MITRE technique → phase mapping (technique prefix is enough for base techniques)
_TECHNIQUE_TO_PHASE: dict[str, str] = {
    # Reconnaissance
    'T1595': 'reconnaissance', 'T1592': 'reconnaissance', 'T1591': 'reconnaissance',
    'T1590': 'reconnaissance', 'T1589': 'reconnaissance', 'T1598': 'reconnaissance',
    'T1597': 'reconnaissance', 'T1596': 'reconnaissance', 'T1593': 'reconnaissance',
    'T1594': 'reconnaissance',
    # Initial access
    'T1190': 'initial_access', 'T1133': 'initial_access', 'T1200': 'initial_access',
    'T1566': 'initial_access', 'T1091': 'initial_access', 'T1195': 'initial_access',
    'T1199': 'initial_access', 'T1078': 'initial_access', 'T1189': 'initial_access',
    # Execution
    'T1059': 'execution', 'T1203': 'execution', 'T1204': 'execution',
    'T1569': 'execution', 'T1106': 'execution', 'T1129': 'execution',
    'T1053': 'execution', 'T1047': 'execution', 'T1072': 'execution',
    'T1559': 'execution', 'T1610': 'execution',
    # Persistence
    'T1098': 'persistence', 'T1136': 'persistence', 'T1543': 'persistence',
    'T1546': 'persistence', 'T1547': 'persistence', 'T1574': 'persistence',
    'T1505': 'persistence', 'T1525': 'persistence', 'T1176': 'persistence',
    'T1556': 'persistence', 'T1053': 'persistence',  # scheduled task can be both
    # Privilege escalation
    'T1548': 'privilege_escalation', 'T1134': 'privilege_escalation',
    'T1484': 'privilege_escalation', 'T1611': 'privilege_escalation',
    'T1068': 'privilege_escalation', 'T1078': 'privilege_escalation',
    'T1055': 'privilege_escalation',
    # Lateral movement
    'T1021': 'lateral_movement', 'T1534': 'lateral_movement',
    'T1550': 'lateral_movement', 'T1563': 'lateral_movement',
    'T1570': 'lateral_movement', 'T1210': 'lateral_movement',
    'T1080': 'lateral_movement',
    # Collection
    'T1005': 'collection', 'T1025': 'collection', 'T1039': 'collection',
    'T1074': 'collection', 'T1114': 'collection', 'T1113': 'collection',
    'T1560': 'collection', 'T1115': 'collection', 'T1123': 'collection',
    'T1119': 'collection', 'T1185': 'collection',
    # Exfiltration
    'T1041': 'exfiltration', 'T1048': 'exfiltration', 'T1052': 'exfiltration',
    'T1567': 'exfiltration', 'T1029': 'exfiltration', 'T1020': 'exfiltration',
    'T1030': 'exfiltration', 'T1022': 'exfiltration',
    # Impact
    'T1485': 'impact', 'T1486': 'impact', 'T1489': 'impact',
    'T1490': 'impact', 'T1491': 'impact', 'T1498': 'impact',
    'T1499': 'impact', 'T1531': 'impact', 'T1657': 'impact',
    'T1561': 'impact', 'T1496': 'impact',
}

# Label thresholds
_STAGE_LABELS = [
    (7, 'Full-Cycle'),          # 7–9 phases
    (5, 'Late-Stage'),          # 5–6 phases
    (3, 'Mid-Stage'),           # 3–4 phases
    (1, 'Early-Stage'),         # 1–2 phases
    (0, 'No Kill-Chain Signal'),
]


def _technique_to_base(tid: str) -> str:
    """Strip sub-technique suffix: T1003.001 → T1003."""
    return tid.split('.')[0].upper() if tid else tid


def score_cluster_kill_chain(cluster: dict, rows: list[dict]) -> None:
    """Score kill-chain completeness for *cluster* and mutate it in-place.

    Sets:
      ``kill_chain_phases_observed``  — sorted list of phase names
      ``kill_chain_completeness``     — float 0.0–1.0
      ``kill_chain_gaps``             — phases not yet seen
      ``kill_chain_stage_label``      — e.g. 'Late-Stage'
      ``kill_chain_phase_count``      — int
    """
    # Collect all MITRE tags from cluster-level and per-row
    all_mitre: set[str] = set()
    for tag in cluster.get('top_mitre') or []:
        all_mitre.add(_technique_to_base(str(tag)))
    for row in rows or []:
        for tag in row.get('mitre') or []:
            all_mitre.add(_technique_to_base(str(tag)))

    phases_seen: set[str] = set()
    for tid in all_mitre:
        phase = _TECHNIQUE_TO_PHASE.get(tid)
        if phase:
            phases_seen.add(phase)

    phases_ordered = [p for p in PHASES if p in phases_seen]
    gaps = [p for p in PHASES if p not in phases_seen]

    completeness = len(phases_seen) / len(PHASES)
    phase_count = len(phases_seen)

    stage_label = 'No Kill-Chain Signal'
    for min_count, label in _STAGE_LABELS:
        if phase_count >= min_count:
            stage_label = label
            break

    cluster['kill_chain_phases_observed'] = phases_ordered
    cluster['kill_chain_completeness'] = round(completeness, 3)
    cluster['kill_chain_gaps'] = gaps
    cluster['kill_chain_stage_label'] = stage_label
    cluster['kill_chain_phase_count'] = phase_count

    # Confidence uplift: each additional phase adds evidence of sustained access
    if phase_count >= 2:
        boost = min(15.0, (phase_count - 1) * 3.0)
        cm = cluster.setdefault('confidence_meter', {})
        cm['total'] = min(100.0, float(cm.get('total') or 0.0) + boost)
        cm['kill_chain_boost'] = boost


# Also provide a standalone MITRE→phase lookup for other callers
def technique_phase(tid: str) -> str | None:
    """Return the kill chain phase for a MITRE technique ID, or None."""
    return _TECHNIQUE_TO_PHASE.get(_technique_to_base(tid))


__all__ = ['score_cluster_kill_chain', 'technique_phase', 'PHASES']
