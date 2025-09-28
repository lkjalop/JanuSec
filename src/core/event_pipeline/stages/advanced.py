from __future__ import annotations

from typing import List

from core.coverage_tracker import get_coverage_tracker
from core.correlation.cluster_dedupe import cluster_mark
from core.correlation.factor_constants import ALL_CORR_FACTORS
from core.correlation.hunt_correlation import get_correlation_engine
from core.embedding.providers import EmbeddingSelector, embed_text
from core.hunt.evidence_envelope import EvidenceEnvelope
from core.hunt.lane_registry import LaneRegistry
from core.mappings.mitre_stride import map_factors
from core.quality.factor_entropy import observe_factors
from core.quality.factor_quality import get_quality_manager

from ..utils import cfg_get
from .base import StageContext, StageResult, timed_stage, maybe_await


@timed_stage('hunt_lanes')
async def hunt_lanes_stage(event: dict, ctx: StageContext) -> StageResult:
    pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
    lane_cfg = cfg_get(pipeline_cfg, 'hunt_lanes', {})
    if not cfg_get(lane_cfg, 'enabled', True):
        return StageResult(name='hunt_lanes', factors=[])

    registry: LaneRegistry | None = ctx.state.get('lane_registry')
    if registry is None:
        registry = LaneRegistry(ctx.config)
        ctx.state['lane_registry'] = registry
        try:
            from core.hunt.lanes.process_lineage import build as build_proc
            registry.register(build_proc())
        except Exception:
            pass
        try:
            from core.hunt.lanes.ja3_novelty import build as build_ja3
            registry.register(build_ja3(ctx.config))
        except Exception:
            pass

    envelope = EvidenceEnvelope(event)
    try:
        await registry.run_lanes(envelope)
    except Exception as exc:
        try:
            ctx.logger.debug('Hunt lanes stage error: %s', exc)
        except Exception:
            pass
        return StageResult(name='hunt_lanes', factors=[])

    factors = list(envelope.lane_factors)
    return StageResult(name='hunt_lanes', factors=factors)


@timed_stage('correlation')
async def correlation_stage(event: dict, ctx: StageContext) -> StageResult:
    if ctx.state.get('correlation_disabled'):
        return StageResult(name='correlation', factors=[])

    pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
    corr_cfg = cfg_get(pipeline_cfg, 'correlation', {})
    if not cfg_get(corr_cfg, 'enabled', True):
        return StageResult(name='correlation', factors=[])

    engine = get_correlation_engine(ctx.config)
    existing = list(ctx.state.get('factors') or [])
    tp_factors: List[str] = []
    fp_factors: List[str] = []
    expected = event.get('expected_verdict')
    if expected in ('malicious', 'benign'):
        for factor in existing:
            if expected == 'malicious' and not factor.startswith('cluster_duplicate'):
                tp_factors.append(factor)
            elif expected == 'benign':
                fp_factors.append(factor)
    else:
        for factor in existing:
            if factor in ALL_CORR_FACTORS or factor.startswith('lane_'):
                tp_factors.append(factor)
            elif factor.startswith('cluster_duplicate') or factor.startswith('timings:'):
                fp_factors.append(factor)
    try:
        new_corr = await engine.correlate(existing, tp_factors=tp_factors, fp_factors=fp_factors)
    except Exception as exc:
        try:
            ctx.logger.debug('Correlation stage error: %s', exc)
        except Exception:
            pass
        return StageResult(name='correlation', factors=[])
    return StageResult(name='correlation', factors=list(new_corr or []))


@timed_stage('quality_filter')
async def quality_stage(event: dict, ctx: StageContext) -> StageResult:
    factors = list(ctx.state.get('factors') or [])
    if not factors:
        return StageResult(name='quality_filter', factors=[])
    try:
        observe_factors(factors)
        qm = get_quality_manager()
        filtered = qm.filter_factors(factors)
    except Exception as exc:
        try:
            ctx.logger.debug('Quality stage error: %s', exc)
        except Exception:
            pass
        return StageResult(name='quality_filter', factors=[])
    if filtered == factors:
        return StageResult(name='quality_filter', factors=[])
    return StageResult(name='quality_filter', factors=[], metadata={'replace_factors': filtered})


@timed_stage('mapping')
async def mapping_stage(event: dict, ctx: StageContext) -> StageResult:
    factors = list(ctx.state.get('factors') or [])
    try:
        mapping_tags = map_factors(factors)
    except Exception as exc:
        try:
            ctx.logger.debug('Mapping stage error: %s', exc)
        except Exception:
            pass
        mapping_tags = []
    return StageResult(name='mapping', factors=list(mapping_tags or []))


@timed_stage('cluster_dedupe')
async def cluster_dedupe_stage(event: dict, ctx: StageContext) -> StageResult:
    factors = list(ctx.state.get('factors') or [])
    if not factors:
        return StageResult(name='cluster_dedupe', factors=[])
    metadata: dict | None = None
    try:
        marks = cluster_mark(factors)
        if marks and any(m.startswith('cluster_duplicate') for m in marks):
            penalty = float(cfg_get(cfg_get(ctx.config, 'pipeline', {}), 'cluster_duplicate_penalty', 0.02) or 0.02)
            metadata = {'confidence_penalty': penalty}
    except Exception as exc:
        try:
            ctx.logger.debug('Cluster stage error: %s', exc)
        except Exception:
            pass
        marks = []
    return StageResult(name='cluster_dedupe', factors=list(marks or []), metadata=metadata)


@timed_stage('coverage_tracker')
async def coverage_stage(event: dict, ctx: StageContext) -> StageResult:
    tracker = get_coverage_tracker()
    try:
        tracker.observe(event.get('tenant_id') or 'default', event)
    except Exception:
        pass
    return StageResult(name='coverage_tracker', factors=[])


@timed_stage('embedding')
async def embedding_stage(event: dict, ctx: StageContext) -> StageResult:
    factors = list(ctx.state.get('factors') or [])
    if not factors:
        return StageResult(name='embedding', factors=[])
    selector: EmbeddingSelector = ctx.state.setdefault('embedding_selector', EmbeddingSelector())  # type: ignore[assignment]
    try:
        await embed_text(' '.join(factors[-50:]), factors, selector)
    except Exception as exc:
        try:
            ctx.logger.warning('Embedding stage error: %s', exc)
        except Exception:
            pass
    return StageResult(name='embedding', factors=[])
