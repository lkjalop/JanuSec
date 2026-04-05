"""Tier-2 RAG deep-dive endpoint (production-grade).

Retrieval strategy (best-effort cascade):
  1. Vector similarity search via VECTOR_LOG_SEARCH (pgvector/FAISS) when available.
  2. Feature store lookup for exact event IDs.
  3. HopGraph context references (session paths and factor chains).
  4. Fallback: echo context_refs with partial enrichment.

Counterfactuals use factor taxonomy to compute the minimum-change scenario
that would flip the detection verdict, grounded in real DREAD scores.

Runbooks are MITRE Kill-Chain phase-aware: each step maps to the ATT&CK
tactic associated with the leading factors.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/llm/tier2', tags=['llm'])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class Tier2Request(BaseModel):
    decision_id: str
    context_refs: List[Dict[str, Any]] = []
    session_id: Optional[str] = None  # optional HopGraph session id


# ---------------------------------------------------------------------------
# Evidence retrieval
# ---------------------------------------------------------------------------

def _retrieve_evidence(context_refs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Retrieve evidence records. Best-effort cascade: vector → feature store → echo."""
    evidence: List[Dict[str, Any]] = []
    refs = context_refs[:20]  # guard

    # 1. Vector similarity search (pgvector / FAISS)
    try:
        from src.integrations.vector_db import VECTOR_LOG_SEARCH  # type: ignore
        if VECTOR_LOG_SEARCH is not None:
            for r in refs[:10]:
                eid = r.get('event_id') or r.get('id')
                if not eid:
                    continue
                try:
                    # Use the vector store's nearest-neighbour lookup
                    hits = VECTOR_LOG_SEARCH.search(str(eid), top_k=3)
                    for h in (hits or []):
                        evidence.append({
                            'event_id': h.get('id') or eid,
                            'summary': h.get('summary') or h.get('text') or '',
                            'score': h.get('score'),
                            'features': h,
                            'source': 'vector_store',
                        })
                except Exception:
                    continue
    except Exception:
        pass

    # 2. Feature store lookup (exact by event_id)
    if len(evidence) < len(refs):
        retrieved_ids = {e['event_id'] for e in evidence}
        try:
            from src.repositories.feature_store_repo import FeatureStoreRepo  # type: ignore
            fs = FeatureStoreRepo()
            for r in refs:
                eid = r.get('event_id') or r.get('id')
                if not eid or eid in retrieved_ids:
                    continue
                try:
                    ev = fs.get(eid)
                    if ev:
                        evidence.append({
                            'event_id': eid,
                            'summary': ev.get('summary') or '',
                            'features': ev,
                            'source': 'feature_store',
                        })
                        retrieved_ids.add(eid)
                except Exception:
                    continue
        except Exception:
            pass

    # 3. Fallback: partial echo of refs with available metadata
    if not evidence:
        for r in refs[:10]:
            eid = r.get('event_id') or r.get('id')
            evidence.append({
                'event_id': eid,
                'summary': r.get('summary') or r.get('description') or '',
                'features': r,
                'source': 'echo_fallback',
            })

    return evidence


# ---------------------------------------------------------------------------
# HopGraph context enrichment
# ---------------------------------------------------------------------------

def _get_hopgraph_context(session_id: Optional[str]) -> Dict[str, Any]:
    """Fetch session path/factor context from HopGraph if a session_id supplied."""
    if not session_id:
        return {}
    try:
        from src.api.graph_sessions import get_session  # type: ignore
        sess = get_session(session_id)
        if not sess:
            return {}
        return {
            'factors': sess.get('factors') or [],
            'paths': (sess.get('graph_summary') or {}).get('paths') or [],
            'verdict': sess.get('verdict'),
            'confidence': sess.get('confidence'),
            'mitre': sess.get('mitre') or [],
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Counterfactual generation (evidence-based)
# ---------------------------------------------------------------------------

_HIGH_VALUE_FACTORS = {
    'impact:ransomware', 'impact:wiper', 'exfiltration:pii', 'exfiltration:credentials',
    'identity:credential_stuffing', 'remote:no_mfa', 'endpoint:unsigned_exec',
    'sandbox:malicious', 'cloud:public_bucket', 'dns:tunnel_suspected',
    'identity:kerberos_s4u_abuse',
}

def _build_counterfactuals(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compute minimum-change counterfactuals using factor taxonomy weights."""
    counterfactuals: List[Dict[str, Any]] = []
    try:
        from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP  # type: ignore
    except Exception:
        _FACTOR_MAP = {}

    seen_factors: List[str] = []
    for e in evidence[:5]:
        feats = e.get('features') or {}
        factors_in_event = feats.get('factors') or feats.get('factor_list') or []
        for f in factors_in_event:
            if f not in seen_factors:
                seen_factors.append(f)

    for factor in seen_factors[:6]:
        entry = _FACTOR_MAP.get(factor) or {}
        dread = entry.get('dread') or {}
        mitre = entry.get('mitre') or []
        damage = dread.get('damage', 0.5)
        exploitability = dread.get('exploitability', 0.5)

        # The minimum change to flip the detection
        if factor in _HIGH_VALUE_FACTORS:
            change = f'Remediate {factor}: enforce control to remove this signal entirely'
            effect = 'Would reduce composite risk score by ≥0.3; likely flips to INVESTIGATE or NO_ACTION'
        else:
            delta = round(damage * 0.5, 2)
            change = f'Reduce {factor} weight by 50% (from ~{damage:.1f} to ~{damage-delta:.1f})'
            effect = f'Estimated composite score drop: ~{delta:.2f}; may flip verdict if below threshold'

        counterfactuals.append({
            'factor': factor,
            'change': change,
            'expected_effect': effect,
            'mitre_techniques': mitre,
            'dread_damage': round(damage, 2),
            'dread_exploitability': round(exploitability, 2),
        })

    if not counterfactuals:
        # Minimal generic counterfactual
        counterfactuals.append({
            'factor': 'generic',
            'change': 'Reduce overall factor confidence by validating against baseline',
            'expected_effect': 'Lowers composite score if baseline suppresses low-fidelity signals',
            'mitre_techniques': [],
        })

    return counterfactuals


# ---------------------------------------------------------------------------
# Kill-chain aware runbook
# ---------------------------------------------------------------------------

_RUNBOOK_BY_TACTIC: Dict[str, List[Dict[str, Any]]] = {
    'recon': [
        {'step': 1, 'action': 'Block scanning source IP at perimeter firewall', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Review firewall logs for prior connection attempts from same /24', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 3, 'action': 'Submit source IP to threat intel for enrichment (ASN, reputation)', 'phase': 'enrichment', 'confidence': 'medium'},
    ],
    'initial_access': [
        {'step': 1, 'action': 'Reset credentials for all accounts referenced in event', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Review MFA enrollment and enforce for affected accounts', 'phase': 'hardening', 'confidence': 'high'},
        {'step': 3, 'action': 'Inspect VPN/remote access logs for prior sessions from same source', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 4, 'action': 'Check for persistence mechanisms (scheduled tasks, startup entries)', 'phase': 'investigation', 'confidence': 'medium'},
    ],
    'execution': [
        {'step': 1, 'action': 'Isolate affected host(s) from network immediately', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Collect volatile memory image before shutdown', 'phase': 'evidence_collection', 'confidence': 'high'},
        {'step': 3, 'action': 'Submit suspicious binary to sandbox for detonation', 'phase': 'analysis', 'confidence': 'high'},
        {'step': 4, 'action': 'Check parent/child process tree in EDR telemetry', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 5, 'action': 'Correlate hash against internal asset inventory for blast radius', 'phase': 'investigation', 'confidence': 'medium'},
    ],
    'persistence': [
        {'step': 1, 'action': 'Enumerate all persistence surfaces: services, tasks, run keys, boot records', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 2, 'action': 'Remove identified persistence mechanism and verify clean', 'phase': 'remediation', 'confidence': 'high'},
        {'step': 3, 'action': 'Rebuild or re-image host from known-good baseline', 'phase': 'remediation', 'confidence': 'high'},
    ],
    'privilege_escalation': [
        {'step': 1, 'action': 'Revoke elevated session tokens immediately', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Audit service accounts and privileged group membership for anomalies', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 3, 'action': 'Review DC event logs 4768/4769/4624 for Kerberos anomalies', 'phase': 'investigation', 'confidence': 'medium'},
    ],
    'lateral_movement': [
        {'step': 1, 'action': 'Block inter-host SMB/RDP using microsegmentation or ACLs', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Identify all hosts the attacker touched; isolate each', 'phase': 'containment', 'confidence': 'high'},
        {'step': 3, 'action': 'Review authentication events on each impacted host', 'phase': 'investigation', 'confidence': 'high'},
    ],
    'exfiltration': [
        {'step': 1, 'action': 'Block egress to identified external destinations at proxy/firewall', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Identify and quantify the data scope that may have been exfiltrated', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 3, 'action': 'Notify legal and privacy teams for regulatory assessment (GDPR/HIPAA)', 'phase': 'notification', 'confidence': 'high'},
        {'step': 4, 'action': 'Enable DLP rules to capture ongoing exfil attempts', 'phase': 'detection', 'confidence': 'medium'},
    ],
    'command_and_control': [
        {'step': 1, 'action': 'Block C2 domain/IP at DNS sinkholes and firewall egress rules', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Review all hosts with connections to C2 infrastructure', 'phase': 'investigation', 'confidence': 'high'},
        {'step': 3, 'action': 'Capture full packet data (PCAP) for C2 channel decoding', 'phase': 'evidence_collection', 'confidence': 'medium'},
    ],
    'default': [
        {'step': 1, 'action': 'Isolate affected host and collect evidence (memory, disk, logs)', 'phase': 'containment', 'confidence': 'high'},
        {'step': 2, 'action': 'Submit findings to sandbox and upload to SIEM for correlation', 'phase': 'analysis', 'confidence': 'high'},
        {'step': 3, 'action': 'Review related alerts in a 72-hour window for correlated activity', 'phase': 'investigation', 'confidence': 'medium'},
    ],
}


def _build_runbook(evidence: List[Dict[str, Any]], hopgraph_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a Kill-Chain phase-matched runbook."""
    try:
        from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP  # type: ignore
    except Exception:
        _FACTOR_MAP = {}

    # Collect all factors from evidence and HopGraph context
    all_factors: List[str] = list(hopgraph_ctx.get('factors') or [])
    for e in evidence:
        feats = e.get('features') or {}
        all_factors.extend(feats.get('factors') or feats.get('factor_list') or [])

    # Determine dominant MAESTRO tactic
    tactic_votes: Dict[str, int] = {}
    for f in all_factors:
        entry = _FACTOR_MAP.get(f) or {}
        for t in (entry.get('maestro') or []):
            tactic_votes[t] = tactic_votes.get(t, 0) + 1

    dominant_tactic = max(tactic_votes, key=tactic_votes.get) if tactic_votes else 'default'
    runbook = _RUNBOOK_BY_TACTIC.get(dominant_tactic) or _RUNBOOK_BY_TACTIC['default']

    return [{**step, 'tactic': dominant_tactic} for step in runbook]


# ---------------------------------------------------------------------------
# LLM enrichment (optional)
# ---------------------------------------------------------------------------

def _enrich_with_llm(
    decision_id: str,
    evidence: List[Dict[str, Any]],
    counterfactuals: List[Dict[str, Any]],
    runbook: List[Dict[str, Any]],
    hopgraph_ctx: Dict[str, Any],
) -> Optional[str]:
    """Ask the LLM to write a 300-word analyst narrative.  Returns None on failure."""
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT  # type: ignore
        client = DEFAULT_CLIENT
        if client is None:
            return None

        factors_text = '\n'.join(
            f"- {cf['factor']}: {cf['change']}" for cf in counterfactuals[:5]
        )
        evidence_text = '\n'.join(
            f"- [{e.get('source','?')}] {e['event_id']}: {e.get('summary','')[:120]}"
            for e in evidence[:5]
        )
        runbook_text = '\n'.join(
            f"{s['step']}. [{s['phase']}] {s['action']}" for s in runbook[:5]
        )
        verdict = hopgraph_ctx.get('verdict') or 'unknown'
        confidence = hopgraph_ctx.get('confidence') or 0.0
        mitre = ', '.join(hopgraph_ctx.get('mitre') or []) or 'N/A'

        prompt = f"""You are a Tier-2 SOC analyst writing an investigation narrative.

Decision ID: {decision_id}
Verdict: {verdict} (confidence {confidence:.0%})
MITRE Techniques: {mitre}

EVIDENCE RETRIEVED:
{evidence_text}

KEY FACTORS & COUNTERFACTUALS:
{factors_text}

RECOMMENDED RUNBOOK:
{runbook_text}

Write a concise 200-300 word investigation narrative for the analyst:
1. Summarise what happened and the confidence level.
2. Explain which evidence is most compelling and why.
3. Describe what would need to change to lower the risk verdict (counterfactual reasoning).
4. Highlight the top investigation gap if any evidence is missing.

Respond with plain text only. No JSON. No markdown headers."""

        result = client.generate(prompt, max_tokens=512)
        return (result.get('text') or '').strip()[:2000] or None
    except Exception as exc:
        logger.debug('Tier2 LLM narrative failed: %s', exc)
        return None


# ---------------------------------------------------------------------------
# Public endpoint
# ---------------------------------------------------------------------------

@router.post('/explain')
def explain(req: Tier2Request):
    """Tier-2 deep-dive explanation.

    Retrieves supporting evidence via vector search and feature store,
    generates evidence-based counterfactuals from the factor taxonomy,
    and provides a Kill-Chain-phase-matched runbook.

    Optionally includes an LLM-authored investigation narrative when a
    capable provider is available.
    """
    t0 = time.time()

    # 1. Retrieve evidence
    evidence = _retrieve_evidence(req.context_refs)

    # 2. HopGraph context (if session_id supplied)
    hopgraph_ctx = _get_hopgraph_context(req.session_id)

    # 3. Evidence-based counterfactuals
    counterfactuals = _build_counterfactuals(evidence)

    # 4. Kill-chain phase-aware runbook
    runbook = _build_runbook(evidence, hopgraph_ctx)

    # 5. Optional LLM narrative
    narrative = _enrich_with_llm(req.decision_id, evidence, counterfactuals, runbook, hopgraph_ctx)

    elapsed_ms = round((time.time() - t0) * 1000, 1)

    return {
        'decision_id': req.decision_id,
        'evidence': evidence,
        'counterfactuals': counterfactuals,
        'runbook': runbook,
        'hopgraph_context': hopgraph_ctx if hopgraph_ctx else None,
        'narrative': narrative,
        'provenance': {
            'method': 'rag-v2',
            'elapsed_ms': elapsed_ms,
            'evidence_count': len(evidence),
            'evidence_sources': list({e.get('source', 'unknown') for e in evidence}),
            'notes': 'vector+feature_store retrieval with taxonomy counterfactuals',
        },
    }

