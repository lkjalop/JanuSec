"""Corrective RAG (CRAG) adversarial grader for correlation clusters.

The grader evaluates a cluster's supporting evidence against three adversarial
questions and returns a structured verdict used by the on-demand enrichment
endpoint to decide whether to accept, refine, or reject an LLM-generated
cluster narrative.

Grading dimensions
------------------
1. Evidence sufficiency  — Is there enough raw evidence to support the claim?
2. False-positive risk   — Do benign signals dominate or undermine the cluster?
3. Chain coherence       — Does the attack chain logically hang together?

Each dimension scores 0.0–1.0.  The composite grade is the weighted mean:
  composite = 0.4 * sufficiency + 0.35 * coherence + 0.25 * (1 - fp_risk)

Verdict thresholds
------------------
  >= 0.72  → ACCEPT   (cluster narrative is well-supported; proceed to enrich)
  >= 0.45  → REFINE   (gap exists; enrichment should add caveats / ask for more)
  <  0.45  → REJECT   (evidence too thin or FP-dominated; do not escalate)

The module is intentionally LLM-free — all signals are rule-based so it can
run synchronously inside the cluster builder without adding latency.
"""
from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_ACCEPT_THRESHOLD = 0.72
_REFINE_THRESHOLD = 0.45

# Weight of each dimension in the composite score
_W_SUFFICIENCY = 0.40
_W_COHERENCE   = 0.35
_W_FP          = 0.25   # weighted as (1 - fp_risk)

# ---------------------------------------------------------------------------
# Kill-chain phase ordering used to assess chain coherence
# ---------------------------------------------------------------------------
_PHASE_ORDER: Dict[str, int] = {
    'initial_access':       1,
    'execution':            2,
    'persistence':          3,
    'privilege_escalation': 4,
    'defense_evasion':      4,
    'credential_access':    5,
    'discovery':            5,
    'lateral_movement':     6,
    'collection':           7,
    'command_and_control':  7,
    'exfiltration':         8,
    'impact':               9,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def grade_cluster(cluster: Dict[str, Any]) -> Dict[str, Any]:
    """Grade a cluster dict returned by _build_correlation_clusters.

    Parameters
    ----------
    cluster:
        A cluster dict as produced by deep_analyze_endpoints._build_correlation_clusters.

    Returns
    -------
    dict with keys:
      verdict         — "ACCEPT" | "REFINE" | "REJECT"
      composite       — float 0.0–1.0
      sufficiency     — float 0.0–1.0
      fp_risk         — float 0.0–1.0  (higher = more FP risk)
      coherence       — float 0.0–1.0
      reasons         — List[str]  human-readable reasoning lines
      caveats         — List[str]  caveats the enrichment prompt should include
      escalate        — bool       True when verdict == ACCEPT
    """
    sufficiency, suf_reasons, suf_caveats = _score_sufficiency(cluster)
    fp_risk,     fp_reasons,  fp_caveats  = _score_fp_risk(cluster)
    coherence,   coh_reasons, coh_caveats = _score_coherence(cluster)

    composite = (
        _W_SUFFICIENCY * sufficiency
        + _W_COHERENCE   * coherence
        + _W_FP          * (1.0 - fp_risk)
    )
    composite = round(min(max(composite, 0.0), 1.0), 3)

    if composite >= _ACCEPT_THRESHOLD:
        verdict = 'ACCEPT'
    elif composite >= _REFINE_THRESHOLD:
        verdict = 'REFINE'
    else:
        verdict = 'REJECT'

    reasons  = suf_reasons  + fp_reasons  + coh_reasons
    caveats  = suf_caveats  + fp_caveats  + coh_caveats

    return {
        'verdict':      verdict,
        'composite':    composite,
        'sufficiency':  round(sufficiency, 3),
        'fp_risk':      round(fp_risk, 3),
        'coherence':    round(coherence, 3),
        'reasons':      reasons,
        'caveats':      caveats,
        'escalate':     verdict == 'ACCEPT',
    }


# ---------------------------------------------------------------------------
# Dimension scorers
# ---------------------------------------------------------------------------

def _score_sufficiency(
    cluster: Dict[str, Any],
) -> tuple[float, List[str], List[str]]:
    """Score how well the cluster is backed by raw evidence (0.0–1.0)."""
    reasons: List[str] = []
    caveats: List[str] = []
    score = 0.0

    row_count = len(cluster.get('row_refs') or [])
    # Row count contribution (capped at 0.35 — quantity is not quality)
    if row_count >= 5:
        score += 0.35
        reasons.append(f'{row_count} rows — strong evidence volume')
    elif row_count >= 3:
        score += 0.25
        reasons.append(f'{row_count} rows — adequate evidence volume')
    elif row_count >= 2:
        score += 0.15
        reasons.append(f'{row_count} rows — minimal evidence volume')
        caveats.append('Only 2 correlated rows — verify whether further activity exists.')
    else:
        caveats.append('Fewer than 2 rows — insufficient raw evidence for a cluster narrative.')

    # Source diversity contribution (capped at 0.25)
    n_sources = len(set(cluster.get('source_sheets') or []))
    if n_sources >= 3:
        score += 0.25
        reasons.append(f'{n_sources} independent sources corroborate')
    elif n_sources == 2:
        score += 0.15
        reasons.append('2 independent sources corroborate')
    elif n_sources == 1:
        score += 0.05
        caveats.append('Single-source cluster — self-corroboration; seek cross-source validation.')

    # Shared entity contribution (accounts, hosts, IPs) — up to 0.20
    n_entities = (
        len(cluster.get('shared_accounts') or [])
        + len(cluster.get('shared_hosts') or [])
        + len(cluster.get('shared_external_ips') or [])
    )
    if n_entities >= 3:
        score += 0.20
        reasons.append(f'{n_entities} shared entities across rows')
    elif n_entities >= 1:
        score += 0.10
        reasons.append(f'{n_entities} shared entity/entities across rows')
    else:
        caveats.append('No shared accounts, hosts, or IPs — correlation is time/severity-based only.')

    # MITRE coverage (up to 0.10)
    n_mitre = len(cluster.get('top_mitre') or [])
    if n_mitre >= 3:
        score += 0.10
        reasons.append(f'{n_mitre} distinct MITRE techniques mapped')
    elif n_mitre >= 1:
        score += 0.05
        reasons.append(f'{n_mitre} MITRE technique(s) mapped')
    else:
        caveats.append('No MITRE techniques mapped — analyst should tag manually.')

    # Telemetry gap penalty (up to -0.15)
    gaps = (cluster.get('telemetry_gaps') or {}).get('missing_logs') or []
    if len(gaps) >= 4:
        score -= 0.15
        caveats.append(
            f'{len(gaps)} telemetry gaps — critical attack paths may be unvalidated. '
            'Collect missing sources before escalating.'
        )
    elif len(gaps) >= 2:
        score -= 0.07
        caveats.append(f'{len(gaps)} telemetry gaps reduce evidence completeness.')

    # Impossible travel bonus (strong signal = +0.05)
    if cluster.get('has_impossible_travel_elevated'):
        score += 0.05
        reasons.append('Impossible travel + elevated credential signal detected')

    return min(max(score, 0.0), 1.0), reasons, caveats


def _score_fp_risk(
    cluster: Dict[str, Any],
) -> tuple[float, List[str], List[str]]:
    """Estimate false-positive risk (0.0 = no FP risk, 1.0 = certain FP).

    Higher score = more FP risk.
    """
    reasons: List[str] = []
    caveats: List[str] = []
    risk = 0.0

    # Explicit FP flag
    if cluster.get('fp_flag'):
        risk += 0.40
        neg = cluster.get('likely_fp_context') or []
        if neg:
            reasons.append(f'Matched benign patterns: {", ".join(neg[:3])}')
            caveats.append(
                'Benign pattern match — provide explicit deny-benign justification '
                'before treating this cluster as malicious.'
            )
        fp_ratio = cluster.get('fp_ratio') or 0.0
        if fp_ratio >= 0.40:
            reasons.append(f'{int(fp_ratio * 100)}% of rows carry benign/reviewed-FP markers')
            caveats.append(
                'High proportion of benign-annotated rows. '
                'Investigate whether this is a known-good workflow before escalating.'
            )

    # Baseline noise
    bc = cluster.get('baseline_context') or {}
    if bc.get('likely_noise'):
        risk += 0.25
        avg_z = bc.get('avg_z_score', 0)
        reasons.append(f'Baseline z={avg_z:.1f} — activity is baseline-normal')
        caveats.append(
            f'Baseline z-score avg {avg_z:.1f} indicates this is likely normal activity. '
            'Verify against known-good baselines before proceeding.'
        )
    elif bc.get('anomalous'):
        # Genuinely anomalous baseline reduces FP risk
        risk -= 0.10
        reasons.append('Baseline confirms anomalous activity (z ≥ 3.0)')

    # Confidence below threshold
    conf = cluster.get('confidence') or 0.0
    if conf < 0.35:
        risk += 0.20
        reasons.append(f'Confidence {conf:.2f} is below reliable-evidence threshold')
        caveats.append('Low cluster confidence — do not auto-escalate without additional verification.')
    elif conf >= 0.75:
        risk -= 0.10
        reasons.append(f'Confidence {conf:.2f} supports evidence quality')

    # Single-source with no entity overlap is high FP risk
    n_sources = len(set(cluster.get('source_sheets') or []))
    n_entities = (
        len(cluster.get('shared_accounts') or [])
        + len(cluster.get('shared_hosts') or [])
        + len(cluster.get('shared_external_ips') or [])
    )
    if n_sources <= 1 and n_entities == 0:
        risk += 0.20
        caveats.append(
            'Single-source cluster with no shared entities — '
            'elevated false-positive risk without cross-source corroboration.'
        )

    return min(max(risk, 0.0), 1.0), reasons, caveats


def _score_coherence(
    cluster: Dict[str, Any],
) -> tuple[float, List[str], List[str]]:
    """Score how logically coherent the attack chain is (0.0–1.0)."""
    reasons: List[str] = []
    caveats: List[str] = []
    score = 0.0

    # Phase sequence from tag_cluster_phases
    phase_seq = cluster.get('phase_sequence') or []
    ordered = [_PHASE_ORDER.get(p) for p in phase_seq if p in _PHASE_ORDER]
    ordered = [x for x in ordered if x is not None]

    if len(ordered) >= 3:
        score += 0.35
        reasons.append(f'Kill-chain phase sequence spans {len(ordered)} phases ({", ".join(phase_seq[:4])})')
    elif len(ordered) == 2:
        score += 0.20
        reasons.append(f'2-phase kill-chain progression ({", ".join(phase_seq[:2])})')
    elif len(ordered) == 1:
        score += 0.08
        reasons.append(f'Single kill-chain phase ({phase_seq[0]})')
        caveats.append('Only one kill-chain phase mapped — chain may be incomplete.')
    else:
        caveats.append('No kill-chain phase sequence — chain coherence cannot be assessed automatically.')

    # Forward-moving sequence bonus: phases in ascending order
    if len(ordered) >= 2:
        forwards = sum(1 for a, b in zip(ordered, ordered[1:]) if b > a)
        backwards = sum(1 for a, b in zip(ordered, ordered[1:]) if b < a)
        if backwards == 0 and forwards >= 2:
            score += 0.20
            reasons.append('Phase sequence is strictly forward-moving (no phase regression)')
        elif backwards > 0:
            caveats.append(
                f'{backwards} phase regression(s) in kill-chain sequence — '
                'may indicate mixed campaigns or event ordering artefacts.'
            )

    # Attack chain text quality
    ac = cluster.get('attack_chain') or {}
    chain_text = ac.get('chain_text') or ''
    if '->' in chain_text:
        steps = [s.strip() for s in chain_text.split('->') if s.strip()]
        score += min(0.20, 0.07 * len(steps))
        reasons.append(f'Attack chain has {len(steps)} named steps: {chain_text[:80]}')
    elif chain_text and 'no attack chain' not in chain_text.lower():
        score += 0.05
        reasons.append(f'Attack chain present: {chain_text[:60]}')
    else:
        caveats.append('No attack chain identified from factor mapping — add MITRE tags to improve coherence scoring.')

    # Scenario diversity bonus
    scenarios = ac.get('scenarios') or []
    n_sc = len(scenarios)
    if n_sc >= 3:
        score += 0.15
        reasons.append(f'{n_sc} distinct attack scenarios mapped')
    elif n_sc >= 1:
        score += 0.07
        reasons.append(f'{n_sc} attack scenario(s) mapped')

    # Reason summary existence
    reason_summary = cluster.get('reason_summary') or ''
    if reason_summary and len(reason_summary) > 10:
        score += 0.10
        reasons.append('Correlation reason summary is present')
    else:
        caveats.append('No correlation reason summary — check pair-reason coverage for component rows.')

    return min(max(score, 0.0), 1.0), reasons, caveats


__all__ = ['grade_cluster']
