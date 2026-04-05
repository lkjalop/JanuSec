from __future__ import annotations

from typing import Any, Dict, List

from core.detectors.api_security import analyze_api_event, is_api_event
from core.graph.hopgraph_lite import get_graph

from .base import StageContext, StageResult, timed_stage


def _enrichment_bucket(ctx: StageContext) -> Dict[str, Any]:
    cache = ctx.state.setdefault('enrichment_cache', {})
    return cache.setdefault('api_security', {
        'alerts': [],
        'pii_matches': [],
        'forensics': [],
        'missing_logs': [],
    })


@timed_stage('api_security')
async def api_security_stage(event: dict[str, Any], ctx: StageContext) -> StageResult:
    if not is_api_event(event):
        return StageResult(name='api_security', factors=[])

    analysis = analyze_api_event(event)
    factors = list(analysis.factors)
    metadata: Dict[str, Any] = {}

    if analysis.alerts or analysis.pii_matches or analysis.missing_logs:
        bucket = _enrichment_bucket(ctx)
        if analysis.alerts:
            bucket['alerts'].extend(analysis.alerts)
        if analysis.pii_matches:
            bucket['pii_matches'].extend(analysis.pii_matches)
        if analysis.forensics:
            bucket['forensics'].extend(analysis.forensics)
        if analysis.missing_logs:
            bucket_missing = bucket.setdefault('missing_logs', [])
            for item in analysis.missing_logs:
                if item not in bucket_missing:
                    bucket_missing.append(item)
        # Record summary for Tier1/Tier2 prompts
        if analysis.llm_context:
            bucket.setdefault('llm_context', []).append(analysis.llm_context)

    if analysis.missing_logs:
        cache = ctx.state.setdefault('enrichment_cache', {})
        missing_store: List[str] = cache.setdefault('missing_logs', [])
        for item in analysis.missing_logs:
            if item not in missing_store:
                missing_store.append(item)

    if analysis.hopgraph_observations:
        graph = get_graph()
        for obs in analysis.hopgraph_observations:
            try:
                graph.observe(obs)
            except Exception:
                continue

    if analysis.alerts:
        metadata['api_security_alerts'] = analysis.alerts
    if analysis.pii_matches:
        metadata['api_security_pii'] = analysis.pii_matches
    if analysis.missing_logs:
        metadata['missing_logs'] = analysis.missing_logs
    if analysis.forensics:
        metadata['api_security_timeline'] = analysis.forensics
    if analysis.llm_context.get('scenario_factors'):
        metadata['api_security_scenarios'] = analysis.llm_context.get('scenario_factors')

    return StageResult(
        name='api_security',
        factors=factors,
        confidence_delta=analysis.confidence_delta,
        metadata=metadata or None,
    )
