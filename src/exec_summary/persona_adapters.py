"""Persona adapters — reframe cluster narratives for different audiences.

Rather than regenerating narratives from scratch, these adapters reshape
the existing ClusterNarrative and rollup into audience-specific framing.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .schemas import ClusterNarrative, PersonaNarrative

logger = logging.getLogger(__name__)


# ── Persona framing definitions ───────────────────────────────────────────────

_PERSONA_CONFIG: dict[str, dict[str, str]] = {
    'executive': {
        'emphasis': 'Business impact, financial exposure, regulatory risk, and recommended board-level actions',
        'instruction': 'Rewrite for a board audience. Lead with monetary/regulatory exposure. Omit technical jargon.',
    },
    'ciso': {
        'emphasis': 'Risk posture, control gaps, strategic containment, and program maturity implications',
        'instruction': 'Rewrite for CISO. Focus on risk metrics, control effectiveness, and strategic response.',
    },
    'soc_analyst': {
        'emphasis': 'IOCs, affected hosts/accounts, MITRE techniques, and immediate triage actions',
        'instruction': 'Rewrite for SOC analyst. Emphasize IOCs, TTPs, host/account lists, and triage steps.',
    },
    'threat_hunter': {
        'emphasis': 'TTPs, lateral movement patterns, persistence mechanisms, and pivot opportunities',
        'instruction': 'Rewrite for threat hunter. Focus on attacker tradecraft, pivots, and hunting hypotheses.',
    },
    'forensics': {
        'emphasis': 'Evidence preservation, chain of custody, timeline reconstruction, artifact locations',
        'instruction': 'Rewrite for forensics team. Focus on evidence integrity, artefact locations, and timeline precision.',
    },
    'compliance': {
        'emphasis': 'Regulatory obligations, notification deadlines, data classification, breach impact assessment',
        'instruction': 'Rewrite for compliance/legal. Focus on regulatory triggers, notification timelines, and data class exposure.',
    },
    'mssp': {
        'emphasis': 'Multi-tenant context, SLA obligations, escalation paths, cross-tenant pattern matching',
        'instruction': 'Rewrite for MSSP operator. Focus on tenant isolation, SLA compliance, and escalation routing.',
    },
}


def adapt_for_persona(
    persona: str,
    cluster_narrative: ClusterNarrative,
    llm_func: Optional[Any] = None,
    model: str = 'qwen3:14b',
) -> PersonaNarrative:
    """Reframe a single cluster narrative for a specific persona.

    Uses LLM when available; falls back to deterministic emphasis tagging.
    """
    config = _PERSONA_CONFIG.get(persona)
    if not config:
        return PersonaNarrative(
            persona=persona,
            cluster_id=cluster_narrative.cluster_id,
            framing='unknown persona',
            emphasis='',
            summary=cluster_narrative.summary_paragraph,
        )

    # Deterministic fallback — prepend emphasis context
    deterministic_summary = (
        f'[{persona.upper()} perspective — {config["emphasis"]}] '
        f'{cluster_narrative.summary_paragraph}'
    )

    if not llm_func:
        return PersonaNarrative(
            persona=persona,
            cluster_id=cluster_narrative.cluster_id,
            framing=config['emphasis'],
            emphasis=config['emphasis'],
            summary=deterministic_summary,
        )

    # LLM adaptation
    prompt = (
        f'{config["instruction"]}\n\n'
        f'ORIGINAL NARRATIVE (cluster: {cluster_narrative.incident_name}, '
        f'verdict: {cluster_narrative.verdict}):\n'
        f'{cluster_narrative.summary_paragraph}\n\n'
        f'Belief evolution: {cluster_narrative.belief_trajectory_oneliner}\n'
        f'{cluster_narrative.temporal_context}\n\n'
        'Rewrite in 3-4 sentences. Do not add facts not in the original.'
    )

    try:
        resp = llm_func(prompt, 300, None, {'ollama_model': model}, model)
        text = (resp.get('text') or '').strip()
        if text and len(text) > 30:
            return PersonaNarrative(
                persona=persona,
                cluster_id=cluster_narrative.cluster_id,
                framing=config['emphasis'],
                emphasis=config['emphasis'],
                summary=text,
            )
    except Exception as exc:
        logger.warning('persona adapter LLM failed for %s/%s: %s',
                       persona, cluster_narrative.cluster_id, exc)

    return PersonaNarrative(
        persona=persona,
        cluster_id=cluster_narrative.cluster_id,
        framing=config['emphasis'],
        emphasis=config['emphasis'],
        summary=deterministic_summary,
    )


def adapt_all_personas(
    cluster_narratives: list[ClusterNarrative],
    personas: Optional[list[str]] = None,
    llm_func: Optional[Any] = None,
    model: str = 'qwen3:14b',
    clusters: Optional[list[dict]] = None,
) -> dict[str, list[PersonaNarrative]]:
    """Adapt all cluster narratives for all requested personas.

    Returns {persona_name: [PersonaNarrative per cluster]}.

    When ``clusters`` is supplied, the compliance persona's payload is enriched
    with ``control_failures`` / ``cross_framework_evidence`` / ``regulatory_triggers``
    derived from each cluster's ``control_witnesses`` ledger and tier1_prefill
    metadata.  This is the route that powers the breach.html compliance tab.
    """
    if personas is None:
        personas = list(_PERSONA_CONFIG.keys())

    # Build a {cluster_id: cluster_dict} index so the compliance enricher can
    # look up the original cluster regardless of ordering.
    cluster_index: dict[str, dict] = {}
    if clusters:
        for c in clusters:
            cid = str(c.get('cluster_id') or '')
            if cid:
                cluster_index[cid] = c

    result: dict[str, list[PersonaNarrative]] = {}
    for persona in personas:
        pn_list = []
        for cn in cluster_narratives:
            pn = adapt_for_persona(persona, cn, llm_func, model)
            if persona == 'compliance' and cluster_index:
                _enrich_compliance_persona(pn, cluster_index.get(str(cn.cluster_id)))
            pn_list.append(pn)
        result[persona] = pn_list

    return result


def _enrich_compliance_persona(pn: PersonaNarrative, cluster: Optional[dict]) -> None:
    """Populate the compliance-tab payload from a cluster's ``control_witnesses``
    ledger plus tier1_prefill metadata.

    No-ops when no cluster is supplied or when the cluster has no witnesses
    (e.g., synthetic clusters with no MITRE tags).
    """
    if not isinstance(cluster, dict):
        return
    try:
        from src.core.verdict_engine import (
            witnesses_to_control_failures,
            witnesses_to_cross_framework,
        )
    except Exception as exc:  # pragma: no cover - import safety
        logger.warning('compliance enricher imports failed: %s', exc)
        return

    witnesses = cluster.get('control_witnesses') or {}
    if witnesses:
        pn.control_failures = witnesses_to_control_failures(witnesses)
        pn.cross_framework_evidence = witnesses_to_cross_framework(witnesses)

    prefill = cluster.get('tier1_prefill') or {}
    pasta = prefill.get('pasta_summary') or {}
    business_impact = pasta.get('business_impact') or {}
    triggers: list[dict] = []
    # ── Notifiable data breach (NDB Scheme) — fires if any control witness is from NDB
    for entry in (pn.control_failures or []):
        if entry.get('framework') == 'NDB Scheme':
            triggers.append({
                'name': 'Notifiable Data Breach (Privacy Act 1988 s26WA)',
                'trigger_id': 'NDB',
                'clock_seconds': 30 * 24 * 3600,
                'rationale': 'Compliance witness mapped to NDB Scheme via MITRE technique '
                              + ', '.join(entry.get('triggered_by') or []) or 'evidence keywords',
            })
            break
    # ── APRA CPS 234 — same trigger logic
    for entry in (pn.control_failures or []):
        if entry.get('framework') == 'APRA CPS 234':
            triggers.append({
                'name': 'APRA CPS 234 — Material Information Security Incident',
                'trigger_id': 'CPS234-Para36',
                'clock_seconds': 72 * 3600,
                'rationale': 'Material info-sec incident; notify APRA within 72h.',
            })
            break
    # Add business-impact-derived triggers if PASTA computed any
    bi_triggers = business_impact.get('regulatory_triggers') if isinstance(business_impact, dict) else None
    if isinstance(bi_triggers, list):
        for t in bi_triggers:
            if isinstance(t, dict):
                triggers.append(t)

    if triggers:
        pn.regulatory_triggers = triggers

    # CVE context — pull from prefill if available (technique → cves map)
    cve_ctx = prefill.get('cve_context') or {}
    if isinstance(cve_ctx, dict) and cve_ctx:
        pn.cve_context = cve_ctx

    # Auditor insights — short list of "questions an auditor would ask"
    insights: list[str] = []
    if pn.control_failures:
        for entry in pn.control_failures[:5]:
            insights.append(
                f"Show the {entry.get('control_id')} control evidence: rows "
                f"{entry.get('evidence_row_ids')} from sources {entry.get('sources')}."
            )
    if insights:
        pn.auditor_insights = insights

    # Remediation roadmap — bucket P1/P2/P3 by failure severity
    if pn.control_failures:
        roadmap: dict[str, list[str]] = {'P1': [], 'P2': [], 'P3': []}
        for entry in pn.control_failures:
            bucket = entry.get('remediation_priority') or 'P3'
            roadmap.setdefault(bucket, []).append(
                f"{entry.get('control_id')} ({entry.get('framework')}) — {entry.get('control_name')}"
            )
        pn.remediation_roadmap = roadmap
