"""Bitemporal analyst review endpoint (T3→T6).

Implements the analyst review loop described in the platform readiness audit:
  T3: Analyst submits labels (confirmed/benign/needs_investigation)
  T4: Bitemporal delta computed (T1 verdict vs T3 label)
  T5: Temporal RAG pattern retrieval fires
  T6: Re-evaluation LLM pass with analyst delta + RAG context (FIRES ACTUAL LLM)

POST /api/v1/assessments/{assessment_id}/analyst_review
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/assessments', tags=['bitemporal'])


class AnalystReviewRequest(BaseModel):
    label: str = Field(
        ...,
        description='Analyst verdict: confirmed_malicious, benign, needs_investigation, false_positive',
    )
    notes: str = Field(default='', max_length=4000, description='Free-text analyst notes')
    analyst: str = Field(default='analyst', max_length=128, description='Analyst identifier')
    persona: str = Field(default='analyst', max_length=64, description='Persona for re-evaluation')


VALID_LABELS = {'confirmed_malicious', 'benign', 'needs_investigation', 'false_positive'}


def _custody_hash(data: dict) -> str:
    canonical = json.dumps({k: data[k] for k in sorted(data) if k != 'custody_hash'}, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _get_assessment(request: Request, assessment_id: str) -> Optional[dict]:
    """Retrieve an assessment from the in-memory REPORT_STORE."""
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        return REPORT_STORE.get(assessment_id)
    except Exception:
        return None


def _compute_bitemporal_delta(t1_verdict: dict, t3_label: str, t3_notes: str) -> dict:
    """Compute the delta between T1 machine verdict and T3 analyst label (T4)."""
    t1_label = (t1_verdict.get('verdict') or t1_verdict.get('action') or 'unknown').lower()
    t1_confidence = float(t1_verdict.get('confidence') or t1_verdict.get('triage_score') or 0.0)

    # Determine if the analyst reversed the machine verdict
    machine_positive = t1_label in ('escalate', 'investigate', 'malicious', 'suspicious', 'confirmed_malicious')
    analyst_positive = t3_label in ('confirmed_malicious', 'needs_investigation')

    label_reversal = machine_positive != analyst_positive
    verdict_escalated = not machine_positive and analyst_positive

    return {
        't1_verdict': t1_label,
        't1_confidence': t1_confidence,
        't3_label': t3_label,
        'label_reversal': label_reversal,
        'verdict_escalated': verdict_escalated,
        'analyst_notes': t3_notes,
        'delta_type': 'reversal' if label_reversal else 'confirmation',
        'computed_at': time.time(),
    }


def _query_temporal_rag(assessment: dict, delta: dict, tenant: str = 'default') -> list[dict]:
    """T5: Query Temporal RAG for similar historical patterns."""
    try:
        from src.ai.temporal_rag import TemporalRAGEngine
        rag = TemporalRAGEngine()

        # Build a query from the delta and assessment context
        query_parts = []
        if delta.get('t3_label'):
            query_parts.append(f"analyst labeled as {delta['t3_label']}")
        if delta.get('analyst_notes'):
            query_parts.append(delta['analyst_notes'][:200])

        # Pull entity info from the assessment
        rows = assessment.get('rows') or []
        for row in rows[:3]:
            for field in ('host', 'user', 'process', 'sourceIPAddress', 'domain'):
                val = row.get(field)
                if val:
                    query_parts.append(str(val))

        query_text = ' '.join(query_parts)
        if not query_text.strip():
            return []

        results = rag.query(query_text, tenant=tenant, top_k=5)
        return results
    except Exception as exc:
        logger.debug("Temporal RAG query failed (graceful degradation): %s", exc)
        return []


def _build_reeval_prompt(assessment: dict, delta: dict, rag_patterns: list, persona: str) -> str:
    """T6: Build re-evaluation prompt incorporating analyst delta + RAG patterns."""
    lines = [
        "BITEMPORAL RE-EVALUATION: An analyst has reviewed this assessment and provided a label.",
        f"Original machine verdict: {delta.get('t1_verdict')} (confidence: {delta.get('t1_confidence', 0):.2f})",
        f"Analyst label: {delta.get('t3_label')}",
        f"Delta type: {delta.get('delta_type')}",
    ]
    if delta.get('label_reversal'):
        lines.append("*** LABEL REVERSAL DETECTED — the analyst disagrees with the machine verdict. ***")
        lines.append("Re-evaluate the evidence considering the analyst's perspective.")
    if delta.get('analyst_notes'):
        lines.append(f"Analyst notes: {delta['analyst_notes']}")
    lines.append("")

    if rag_patterns:
        lines.append("TEMPORAL RAG — SIMILAR HISTORICAL PATTERNS:")
        for i, pattern in enumerate(rag_patterns[:5], 1):
            summary = pattern.get('description') or pattern.get('summary') or str(pattern)[:200]
            lines.append(f"  {i}. {summary}")
        lines.append("")

    lines.append(f"Provide an updated assessment incorporating the analyst's input. Persona: {persona}.")
    return '\n'.join(lines)


async def _fire_t6_llm_reeval(
    assessment: dict,
    delta: dict,
    rag_patterns: list,
    reeval_prompt: str,
    persona: str,
) -> dict:
    """T6: Actually invoke the LLM for re-evaluation and return the updated narrative.

    Returns a dict with keys: llm_response, model_used, tokens_used, error.
    Falls back gracefully — a failed LLM call never blocks the endpoint.
    """
    if os.getenv('LLM_MOCK', '0').lower() in {'1', 'true', 'yes'}:
        return {
            'llm_response': f'[mock] Bitemporal re-evaluation: analyst labelled {delta.get("t3_label")}. '
                            f'Delta type: {delta.get("delta_type")}. '
                            f'RAG patterns used: {len(rag_patterns)}.',
            'model_used': 'mock',
            'tokens_used': 0,
            'error': None,
        }
    try:
        from src.analysis.auto_llm import LLMAssessmentClient, build_tier2_prompt
        client = LLMAssessmentClient()
        # Build a synthetic row from the assessment so the generic prompt builder works
        rows = assessment.get('rows') or [{}]
        representative_row = rows[0] if rows else {}
        context = {
            'tier': 'tier2',
            'persona': persona,
            'reeval_delta': delta,
            'rag_patterns': rag_patterns[:5],
            'bitemporal_reeval': True,
            'reeval_prompt_prefix': reeval_prompt,
        }
        result = client.summarize_row(representative_row, context)
        return {
            'llm_response': result.get('summary') or result.get('response') or str(result),
            'model_used': result.get('model_used') or result.get('model') or 'unknown',
            'tokens_used': result.get('tokens_used') or 0,
            'error': None,
        }
    except Exception as exc:
        logger.warning('T6 LLM re-eval failed (graceful degradation): %s', exc)
        return {
            'llm_response': None,
            'model_used': None,
            'tokens_used': 0,
            'error': str(exc),
        }


@router.post('/{assessment_id}/analyst_review', summary='Submit analyst review (T3→T6 bitemporal)')
async def analyst_review(assessment_id: str, payload: AnalystReviewRequest, request: Request) -> dict:
    """Accept an analyst label, compute bitemporal delta, query RAG, trigger re-eval.

    Writes T3, T4, T5, T6 custody entries to the chain-of-custody log.
    Returns the delta, RAG results, and re-evaluation prompt.
    """
    if payload.label not in VALID_LABELS:
        raise HTTPException(status_code=400, detail=f"invalid_label: must be one of {VALID_LABELS}")

    assessment = _get_assessment(request, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    # Import custody helpers
    try:
        from src.repositories.audit_repo import append_audit, get_last_hash
    except Exception:
        append_audit = None  # type: ignore
        get_last_hash = None  # type: ignore

    tenant = assessment.get('tenant_id') or assessment.get('org') or 'default'
    prev_hash = None
    if get_last_hash:
        prev_hash = await get_last_hash(assessment_id, tenant)

    # --- T3: Record analyst label ---
    t3_details = {
        'label': payload.label,
        'notes': payload.notes,
        'analyst': payload.analyst,
        'persona': payload.persona,
    }
    t3_hash = _custody_hash({'event_id': assessment_id, 'action': 'analyst_label', **t3_details, 'prev_hash': prev_hash})
    if append_audit:
        await append_audit(assessment_id, 'analyst_label', t3_details, t3_hash, prev_hash, tenant)

    # --- T4: Compute bitemporal delta ---
    t1_verdict = {
        'verdict': assessment.get('verdict') or assessment.get('action'),
        'confidence': assessment.get('confidence') or assessment.get('triage_score'),
    }
    delta = _compute_bitemporal_delta(t1_verdict, payload.label, payload.notes)
    t4_hash = _custody_hash({'event_id': assessment_id, 'action': 'bitemporal_delta', **delta, 'prev_hash': t3_hash})
    if append_audit:
        await append_audit(assessment_id, 'bitemporal_delta', delta, t4_hash, t3_hash, tenant)

    # --- T5: Query Temporal RAG (only if delta is a reversal or escalation) ---
    rag_patterns: list = []
    if delta.get('label_reversal') or delta.get('verdict_escalated'):
        rag_patterns = _query_temporal_rag(assessment, delta, tenant=tenant)
        t5_details = {'rag_results_count': len(rag_patterns), 'triggered_by': delta.get('delta_type')}
        t5_hash = _custody_hash({'event_id': assessment_id, 'action': 'temporal_rag_query', **t5_details, 'prev_hash': t4_hash})
        if append_audit:
            await append_audit(assessment_id, 'temporal_rag_query', t5_details, t5_hash, t4_hash, tenant)
    else:
        t5_hash = t4_hash  # no RAG needed for confirmations

    # --- T6: Build re-evaluation prompt ---
    reeval_prompt = _build_reeval_prompt(assessment, delta, rag_patterns, payload.persona)
    t6_details = {
        'reeval_triggered': delta.get('label_reversal') or delta.get('verdict_escalated') or False,
        'prompt_length': len(reeval_prompt),
        'rag_patterns_used': len(rag_patterns),
    }
    t6_hash = _custody_hash({'event_id': assessment_id, 'action': 're_evaluation', **t6_details, 'prev_hash': t5_hash})
    if append_audit:
        await append_audit(assessment_id, 're_evaluation', t6_details, t6_hash, t5_hash, tenant)

    # Update in-memory assessment with review data
    assessment['analyst_review'] = {
        'label': payload.label,
        'notes': payload.notes,
        'analyst': payload.analyst,
        'delta': delta,
        'rag_patterns_count': len(rag_patterns),
        'reeval_triggered': t6_details['reeval_triggered'],
        'reviewed_at': time.time(),
        'version': (assessment.get('analyst_review', {}).get('version', 0) + 1),
    }

    # --- T6: Fire actual LLM re-evaluation (async, only on reversal/escalation) ---
    t6_llm_result: dict = {}
    if t6_details['reeval_triggered']:
        t6_llm_result = await _fire_t6_llm_reeval(
            assessment=assessment,
            delta=delta,
            rag_patterns=rag_patterns,
            reeval_prompt=reeval_prompt,
            persona=payload.persona,
        )
        assessment['analyst_review']['t6_llm_response'] = t6_llm_result.get('llm_response')
        assessment['analyst_review']['t6_model_used'] = t6_llm_result.get('model_used')

    # Publish SSE event for live UI update
    try:
        from src.api.deep_analyze_endpoints import publish_llm_event
        publish_llm_event(assessment_id, {
            'type': 'analyst_review',
            'label': payload.label,
            'delta_type': delta.get('delta_type'),
            'version': assessment['analyst_review']['version'],
        })
    except Exception:
        pass

    return {
        'assessment_id': assessment_id,
        'status': 'reviewed',
        't3_label': payload.label,
        't4_delta': delta,
        't5_rag_patterns': len(rag_patterns),
        't6_reeval_triggered': t6_details['reeval_triggered'],
        't6_llm_response': t6_llm_result.get('llm_response'),
        't6_model_used': t6_llm_result.get('model_used'),
        't6_error': t6_llm_result.get('error'),
        'reeval_prompt': reeval_prompt if t6_details['reeval_triggered'] else None,
        'custody_chain': {
            't3_hash': t3_hash,
            't4_hash': t4_hash,
            't5_hash': t5_hash,
            't6_hash': t6_hash,
        },
        'version': assessment['analyst_review']['version'],
    }


@router.get('/{assessment_id}/custody_chain', summary='Get custody chain for assessment')
async def get_custody_chain(assessment_id: str, request: Request) -> dict:
    """Return the full chain-of-custody entries for an assessment."""
    try:
        from src.repositories.audit_repo import _INMEM_CHAINS, _CHAIN_LOCK
        with _CHAIN_LOCK:
            chain = _INMEM_CHAINS.get(assessment_id)
            if chain:
                return {'assessment_id': assessment_id, 'entries': list(chain), 'count': len(chain)}
    except Exception:
        pass
    return {'assessment_id': assessment_id, 'entries': [], 'count': 0}
