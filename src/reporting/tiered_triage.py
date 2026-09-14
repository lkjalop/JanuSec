"""Tiered triage engine for scaled alert prioritisation.

Handles 20+, 50+, 100+ concurrent alerts by:
  1. Scoring each alert on a composite evidence-based priority (0-100).
  2. Bucketing into urgency tiers (P1-Critical … P4-Informational).
  3. Routing tier-appropriate subsets to each persona with disclosure gating.
  4. Detecting correlation clusters (same campaign / kill-chain stage)
     so analysts see grouped incidents rather than N separate tickets.

The triage output is consumed by:
  - Attention queue (UI dashboard panels)
  - Persona report generation (auto-selecting disclosure level)
  - Human-gated approval layer (auto-escalation triggers)
  - SSE push (real-time analyst notification)

Usage::

    from src.reporting.tiered_triage import triage_alerts, TriageConfig

    results = triage_alerts(alerts, config=TriageConfig())
    # results.tiers -> { 'P1': [...], 'P2': [...], ... }
    # results.persona_queues -> { 'executive': [...], 'soc_analyst': [...], ... }
    # results.clusters -> [ { 'cluster_id', 'alerts', 'common_factors' }, ... ]
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class TriageConfig:
    """Tunable knobs for triage behaviour."""
    # Priority score weight contributions (sum to 1.0)
    w_severity: float = 0.30
    w_confidence: float = 0.25
    w_factor_count: float = 0.15
    w_affected_scope: float = 0.15
    w_asset_criticality: float = 0.15

    # Tier thresholds (on 0-100 composite score)
    p1_threshold: float = 80.0
    p2_threshold: float = 60.0
    p3_threshold: float = 35.0
    # Below p3 -> P4

    # Persona routing: which tiers each persona receives
    persona_tier_map: Dict[str, List[str]] = field(default_factory=lambda: {
        'executive':      ['P1'],
        'soc_analyst':    ['P1', 'P2', 'P3'],
        'compliance':     ['P1', 'P2'],
        'threat_hunter':  ['P1', 'P2', 'P3'],
        'mssp':           ['P1', 'P2'],
        'forensics':      ['P1'],
    })

    # Persona disclosure levels per tier
    persona_disclosure: Dict[str, Dict[str, int]] = field(default_factory=lambda: {
        'executive':      {'P1': 1, 'P2': 1},
        'soc_analyst':    {'P1': 3, 'P2': 2, 'P3': 2},
        'compliance':     {'P1': 2, 'P2': 2},
        'threat_hunter':  {'P1': 3, 'P2': 3, 'P3': 3},
        'mssp':           {'P1': 2, 'P2': 2},
        'forensics':      {'P1': 3},
    })

    # Cluster similarity threshold (Jaccard on factor names)
    cluster_jaccard_threshold: float = 0.4

    # Auto-escalation: P1 alerts pending > N seconds without approval
    auto_escalate_seconds: int = 900  # 15 min

    # Max alerts per persona queue (shed lowest-priority beyond this)
    max_per_persona_queue: int = 50

    # Human gate: require analyst confirmation for P1/P2 before Tier-2 LLM runs
    human_gate_tiers: List[str] = field(default_factory=lambda: ['P1', 'P2'])


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScoredAlert:
    """An alert with composite priority score and tier assignment."""
    alert_id: str
    priority_score: float          # 0-100
    tier: str                      # P1/P2/P3/P4
    severity: str
    verdict: str
    confidence: float
    factor_names: List[str]
    affected_entities: List[str]
    asset_criticality: float
    mitre_tactics: List[str]
    timestamp: float
    raw: Dict[str, Any]

    # Evidence breakdown showing how the score was computed
    score_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class AlertCluster:
    """Group of correlated alerts sharing factors / kill-chain stage."""
    cluster_id: str
    alerts: List[ScoredAlert]
    common_factors: List[str]
    common_mitre: List[str]
    representative_alert_id: str   # highest-scoring alert in the cluster
    aggregate_score: float         # max of member scores


@dataclass
class TriageResult:
    """Complete triage output."""
    tiers: Dict[str, List[ScoredAlert]]
    persona_queues: Dict[str, List[Dict[str, Any]]]
    clusters: List[AlertCluster]
    stats: Dict[str, Any]
    human_gate_required: List[str]  # alert_ids needing analyst confirmation
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10,
}


def _score_alert(alert: Dict[str, Any], cfg: TriageConfig) -> ScoredAlert:
    """Compute composite priority score for a single alert."""
    rq = alert.get('risk_quantification') or {}
    verdict_block = alert.get('verdict') or {}

    severity = (rq.get('severity') or 'LOW').upper()
    verdict = (verdict_block.get('final_verdict') or 'REVIEW').upper()
    confidence = float(verdict_block.get('final_confidence') or 0.0)

    all_factors = verdict_block.get('all_factors') or verdict_block.get('top_contributing_factors') or []
    factor_names = [f.get('factor_name') or f.get('name') or '' for f in all_factors if isinstance(f, dict)]
    factor_count = len(factor_names)

    # Affected entities from timeline
    timeline = alert.get('attack_timeline') or []
    entities: List[str] = []
    seen_ent: Set[str] = set()
    for ev in timeline:
        ent = ev.get('entity') or ''
        if ent and ent not in seen_ent:
            entities.append(ent)
            seen_ent.add(ent)

    # Asset criticality (0-10 scale normalised to 0-1)
    asset_crit = float(
        (alert.get('asset_context') or {}).get('asset_criticality')
        or rq.get('asset_criticality')
        or 5
    ) / 10.0

    # MITRE tactics
    mitre = []
    for f in all_factors:
        if isinstance(f, dict):
            mitre.extend(f.get('mitre', []) if isinstance(f.get('mitre'), list) else [])

    # Component scores (each 0-100)
    s_sev = _SEVERITY_MAP.get(severity, 25)
    s_conf = confidence * 100.0
    s_factors = min(100.0, factor_count * 12.5)  # 8 factors = 100
    s_scope = min(100.0, len(entities) * 20.0)    # 5 entities = 100
    s_asset = asset_crit * 100.0

    # Verdict boost: confirmed THREAT gets +15 on effective severity
    if verdict == 'THREAT':
        s_sev = min(100, s_sev + 15)
    elif verdict == 'SUSPICIOUS':
        s_sev = min(100, s_sev + 5)

    composite = (
        cfg.w_severity * s_sev
        + cfg.w_confidence * s_conf
        + cfg.w_factor_count * s_factors
        + cfg.w_affected_scope * s_scope
        + cfg.w_asset_criticality * s_asset
    )
    composite = round(min(100.0, max(0.0, composite)), 2)

    # Tier assignment
    if composite >= cfg.p1_threshold:
        tier = 'P1'
    elif composite >= cfg.p2_threshold:
        tier = 'P2'
    elif composite >= cfg.p3_threshold:
        tier = 'P3'
    else:
        tier = 'P4'

    return ScoredAlert(
        alert_id=alert.get('report_id') or alert.get('id') or f'anon-{int(time.time()*1000)}',
        priority_score=composite,
        tier=tier,
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        factor_names=factor_names,
        affected_entities=entities,
        asset_criticality=asset_crit,
        mitre_tactics=sorted(set(mitre)),
        timestamp=time.time(),
        raw=alert,
        score_breakdown={
            'severity': round(s_sev, 2),
            'confidence': round(s_conf, 2),
            'factor_count': round(s_factors, 2),
            'affected_scope': round(s_scope, 2),
            'asset_criticality': round(s_asset, 2),
        },
    )


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cluster_alerts(scored: List[ScoredAlert], cfg: TriageConfig) -> List[AlertCluster]:
    """Group alerts by factor overlap (greedy single-pass)."""
    if len(scored) <= 1:
        return []

    assigned: Set[str] = set()
    clusters: List[AlertCluster] = []

    # Sort by score desc so cluster representatives are highest-priority
    sorted_alerts = sorted(scored, key=lambda a: a.priority_score, reverse=True)

    for anchor in sorted_alerts:
        if anchor.alert_id in assigned:
            continue
        group = [anchor]
        assigned.add(anchor.alert_id)
        anchor_factors = set(anchor.factor_names)

        for candidate in sorted_alerts:
            if candidate.alert_id in assigned:
                continue
            cand_factors = set(candidate.factor_names)
            if _jaccard(anchor_factors, cand_factors) >= cfg.cluster_jaccard_threshold:
                group.append(candidate)
                assigned.add(candidate.alert_id)

        if len(group) >= 2:
            common = anchor_factors.copy()
            common_mitre: Set[str] = set(anchor.mitre_tactics)
            for g in group[1:]:
                common &= set(g.factor_names)
                common_mitre &= set(g.mitre_tactics)

            cid = hashlib.sha256(
                '|'.join(sorted(a.alert_id for a in group)).encode()
            ).hexdigest()[:12]

            clusters.append(AlertCluster(
                cluster_id=f'cluster-{cid}',
                alerts=group,
                common_factors=sorted(common),
                common_mitre=sorted(common_mitre),
                representative_alert_id=group[0].alert_id,
                aggregate_score=max(g.priority_score for g in group),
            ))

    return clusters


# ---------------------------------------------------------------------------
# Persona routing
# ---------------------------------------------------------------------------

def _route_to_personas(
    tiers: Dict[str, List[ScoredAlert]],
    cfg: TriageConfig,
) -> Dict[str, List[Dict[str, Any]]]:
    """Build per-persona queues with disclosure level and cap."""
    queues: Dict[str, List[Dict[str, Any]]] = {}

    for persona, allowed_tiers in cfg.persona_tier_map.items():
        items: List[Dict[str, Any]] = []
        disclosure_map = cfg.persona_disclosure.get(persona, {})

        for t in allowed_tiers:
            for sa in tiers.get(t, []):
                items.append({
                    'alert_id': sa.alert_id,
                    'tier': sa.tier,
                    'priority_score': sa.priority_score,
                    'severity': sa.severity,
                    'verdict': sa.verdict,
                    'confidence': sa.confidence,
                    'factor_names': sa.factor_names[:5],
                    'affected_entities': sa.affected_entities[:5],
                    'mitre_tactics': sa.mitre_tactics[:5],
                    'score_breakdown': sa.score_breakdown,
                    'disclosure_level': disclosure_map.get(t, 2),
                    'approval_state': 'PENDING' if sa.tier in cfg.human_gate_tiers else 'APPROVED',
                })

        # Sort by priority desc and cap
        items.sort(key=lambda x: x['priority_score'], reverse=True)
        queues[persona] = items[:cfg.max_per_persona_queue]

    return queues


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def triage_alerts(
    alerts: List[Dict[str, Any]],
    config: TriageConfig | None = None,
) -> TriageResult:
    """Score, tier, cluster, and route alerts to persona queues.

    This is the main entry point. Call it with a batch of alert/report dicts
    (same shape as REPORT_STORE entries or deep-analyze output).

    Returns a ``TriageResult`` with everything the UI / API needs:
      - tiers: P1/P2/P3/P4 buckets
      - persona_queues: per-persona ranked lists with disclosure levels
      - clusters: correlated groups
      - human_gate_required: alert_ids needing analyst confirmation before
        Tier-2 LLM or persona generation proceeds
      - stats: aggregate counts for dashboard
    """
    cfg = config or TriageConfig()

    # 1. Score every alert
    scored: List[ScoredAlert] = []
    for alert in alerts:
        try:
            scored.append(_score_alert(alert, cfg))
        except Exception:
            continue

    # 2. Bucket into tiers
    tiers: Dict[str, List[ScoredAlert]] = {'P1': [], 'P2': [], 'P3': [], 'P4': []}
    for sa in scored:
        tiers[sa.tier].append(sa)
    for tier_list in tiers.values():
        tier_list.sort(key=lambda a: a.priority_score, reverse=True)

    # 3. Cluster correlated alerts
    clusters = _cluster_alerts(scored, cfg)

    # 4. Route to persona queues
    persona_queues = _route_to_personas(tiers, cfg)

    # 5. Identify human-gate-required alerts
    human_gate: List[str] = []
    for t in cfg.human_gate_tiers:
        for sa in tiers.get(t, []):
            human_gate.append(sa.alert_id)

    # 6. Stats
    stats = {
        'total_alerts': len(scored),
        'tier_counts': {t: len(v) for t, v in tiers.items()},
        'cluster_count': len(clusters),
        'clustered_alert_count': sum(len(c.alerts) for c in clusters),
        'human_gate_pending': len(human_gate),
        'persona_queue_sizes': {p: len(q) for p, q in persona_queues.items()},
    }

    return TriageResult(
        tiers=tiers,
        persona_queues=persona_queues,
        clusters=clusters,
        stats=stats,
        human_gate_required=human_gate,
    )
