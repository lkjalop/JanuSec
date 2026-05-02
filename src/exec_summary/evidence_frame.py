"""TemporalRAG-bounded evidence retrieval per cluster.

Calls the existing TemporalRAGEngine.build_context_block() with a query
constructed from cluster evidence, then returns a structured EvidenceFrame.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .schemas import EvidenceFrame, EvidenceSnippet

logger = logging.getLogger(__name__)


def _get_rag_engine() -> Any:
    """Lazy-import the TemporalRAG singleton.

    Returns None when the engine has no indexed data (empty corpus == not
    available), avoiding test-ordering pollution from a freshly initialised
    but empty singleton returning rag_available=False incorrectly.
    """
    try:
        from src.ai.temporal_rag import get_engine
        engine = get_engine()
        # Guard: if no tenant has indexed any events, treat as unavailable.
        corpora = getattr(engine, '_corpora', {})
        if not corpora or not any(len(c) > 0 for c in corpora.values()):
            return None
        return engine
    except Exception:
        return None


def _cluster_query_text(cluster: dict, rows: list[dict]) -> str:
    """Build a query string from cluster evidence for TemporalRAG retrieval."""
    parts: list[str] = []
    prefill = cluster.get('tier1_prefill') or {}

    # Incident name
    name = prefill.get('incident_name') or cluster.get('threat_case_id') or ''
    if name:
        parts.append(name)

    # Key entities
    for field in ('affected_users', 'shared_accounts', 'affected_assets',
                  'shared_hosts', 'shared_external_ips'):
        vals = prefill.get(field) or cluster.get(field) or []
        if isinstance(vals, list):
            parts.extend(str(v) for v in vals[:3] if v)

    # MITRE techniques
    mitre = prefill.get('mitre_techniques') or cluster.get('mitre_tags') or []
    parts.extend(str(t) for t in mitre[:4] if t)

    # Verdict + severity
    verdict = cluster.get('verdict') or cluster.get('final_verdict') or ''
    if verdict:
        parts.append(verdict)

    # First few row descriptions
    for r in rows[:3]:
        desc = r.get('description') or r.get('event_type') or ''
        if desc:
            parts.append(str(desc)[:100])

    return ' '.join(parts)[:512]


def retrieve_evidence_frame(
    cluster: dict,
    rows: list[dict],
    tenant: str = 'default',
    top_k: int = 5,
    window_seconds: int = 7200,
) -> EvidenceFrame:
    """Retrieve TemporalRAG context for a single cluster."""
    cluster_id = str(cluster.get('cluster_id', ''))
    engine = _get_rag_engine()
    if engine is None:
        return EvidenceFrame(cluster_id=cluster_id)

    query_text = _cluster_query_text(cluster, rows)
    if not query_text.strip():
        return EvidenceFrame(cluster_id=cluster_id)

    try:
        ctx = engine.build_context_block(
            query_text=query_text,
            tenant=tenant,
            top_k=top_k,
            window_seconds=window_seconds,
        )
    except Exception as exc:
        logger.debug('evidence_frame TemporalRAG failed for %s: %s', cluster_id, exc)
        return EvidenceFrame(cluster_id=cluster_id)

    snippets = []
    for n in ctx.get('neighbours') or []:
        snippets.append(EvidenceSnippet(
            entity=n.get('entity'),
            severity=n.get('severity'),
            description=str(n.get('description', ''))[:120],
            ts=str(n.get('ts', '')),
            source=n.get('source'),
        ))

    return EvidenceFrame(
        cluster_id=cluster_id,
        rag_available=ctx.get('rag_available', False),
        neighbour_count=ctx.get('neighbour_count', 0),
        window_seconds=ctx.get('window_seconds', window_seconds),
        snippets=snippets,
        summary_hint=ctx.get('summary_hint', ''),
    )
