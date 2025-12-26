from __future__ import annotations

from typing import List

from core.detectors.auth_burst import auth_burst_factors
from core.graph.hopgraph_lite import get_graph
from core.network.packet_summary import summarize_packet_event

from ..utils import cfg_get
from .base import StageContext, StageResult, maybe_await, timed_stage

# Streaming change detector for auth bursts (optional)
try:  # pragma: no cover
    from metrics.streaming import CUSUM_DEFAULT as _CUSUM
except Exception:  # pragma: no cover
    _CUSUM = None  # type: ignore

@timed_stage('baseline')
async def baseline_stage(event: dict, ctx: StageContext) -> StageResult:
    module = await ctx.resolve_module('baseline')
    factors: list[str] = []
    delta = 0.0
    terminal = False
    if module:
        try:
            result = await maybe_await(module.check(event))
            factors.extend(list(getattr(result, 'factors', []) or []))
            delta = float(getattr(result, 'confidence', getattr(result, 'confidence_delta', 0.0)) or 0.0)
            terminal = bool(getattr(result, 'terminal', False))
        except Exception as exc:
            try:
                ctx.logger.debug('Baseline stage error: %s', exc)
            except Exception:
                pass
    return StageResult(name='baseline', factors=factors, confidence_delta=delta, terminal=terminal)


@timed_stage('regex')
async def regex_stage(event: dict, ctx: StageContext) -> StageResult:
    module = await ctx.resolve_module('regex_engine')
    factors: list[str] = []
    delta = 0.0
    if module and hasattr(module, 'analyze_event'):
        try:
            result = await maybe_await(module.analyze_event(event))
            factors.extend(list(getattr(result, 'factors', []) or []))
            delta = float(getattr(result, 'confidence_delta', 0.0) or 0.0)
        except Exception as exc:
            try:
                ctx.logger.debug('Regex stage error: %s', exc)
            except Exception:
                pass
    return StageResult(name='regex', factors=factors, confidence_delta=delta)


SUSPICIOUS_PAIRS = {
    'winword.exe->powershell.exe',
    'excel.exe->powershell.exe',
    'outlook.exe->powershell.exe',
    'wscript.exe->cmd.exe',
    'rundll32.exe->powershell.exe',
    'mshta.exe->powershell.exe',
}


@timed_stage('parent_child')
async def parent_child_stage(event: dict, ctx: StageContext) -> StageResult:
    parent = event.get('parent_process') or event.get('pproc') or {}
    child = event.get('process') or event.get('proc') or {}
    p_name = (parent.get('name') if isinstance(parent, dict) else None) or event.get('parent_name')
    c_name = (child.get('name') if isinstance(child, dict) else None) or event.get('process_name')
    factors: list[str] = []
    if p_name and c_name:
        pair = f"{str(p_name).lower()}->{str(c_name).lower()}"
        if pair in SUSPICIOUS_PAIRS:
            factors.append('suspicious_parent_child_pair')
    if factors:
        ctx.state['parent_child_hit'] = True
    return StageResult(name='parent_child', factors=factors)


@timed_stage('endpoint')
async def endpoint_stage(event: dict, ctx: StageContext) -> StageResult:
    module = await ctx.resolve_module('endpoint_hunter')
    factors: list[str] = []
    delta = 0.0
    if module and hasattr(module, 'analyze_event'):
        try:
            res = await maybe_await(module.analyze_event(event))
            if isinstance(res, dict):
                factors.extend(list(res.get('factors') or []))
                delta = float(res.get('confidence_delta') or 0.0)
        except Exception as exc:
            try:
                ctx.logger.debug('Endpoint stage error: %s', exc)
            except Exception:
                pass
    return StageResult(name='endpoint', factors=factors, confidence_delta=delta)


@timed_stage('auth_burst')
async def auth_burst_stage(event: dict, ctx: StageContext) -> StageResult:
    try:
        factors = auth_burst_factors(event) or []
        # Streaming CUSUM on per-user auth activity (counts)
        user = event.get('user') or event.get('username')
        tenant = event.get('tenant_id') or 'default'
        is_auth_evt = False
        try:
            et = (event.get('event_type') or '').lower()
            details = event.get('details') or {}
            # Restrict to failures for burst spikes to avoid noise
            is_auth_evt = (et in ('auth_fail','login_failed') or (details.get('auth') == 'fail'))
        except Exception:
            is_auth_evt = False
        # Allow gating via config: pipeline.auth_burst.cusum_emit (default True)
        gate = True
        try:
            pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
            ab_cfg = cfg_get(pipeline_cfg, 'auth_burst', {})
            gate = bool(cfg_get(ab_cfg, 'cusum_emit', True))
        except Exception:
            gate = True
        if gate and user and is_auth_evt and _CUSUM is not None:
            out = _CUSUM.update(f"{tenant}::{user}::auth_rate", 1.0)
            if bool(out.get('alarm')):
                factors.append('chg:auth_burst')
    except Exception as exc:
        try:
            ctx.logger.debug('Auth burst stage error: %s', exc)
        except Exception:
            pass
        factors = []
    return StageResult(name='auth_burst', factors=list(factors))


@timed_stage('graph')
async def graph_stage(event: dict, ctx: StageContext) -> StageResult:
    try:
        factors = get_graph().factors(event)
    except Exception as exc:
        try:
            ctx.logger.debug('Graph stage error: %s', exc)
        except Exception:
            pass
        factors = []
    return StageResult(name='graph', factors=list(factors or []))


@timed_stage('adaptive_pre')
async def adaptive_pre_stage(event: dict, ctx: StageContext) -> StageResult:
    pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
    if cfg_get(pipeline_cfg, 'disable_adaptive_pre', False):
        return StageResult(name='adaptive_pre', factors=[])

    tuner = getattr(ctx.config, 'adaptive_tuner', None) or ctx.state.get('adaptive_tuner')
    if tuner is None and hasattr(ctx, 'adaptive_tuner'):
        tuner = ctx.adaptive_tuner
    factors: list[str] = []
    delta = 0.0
    if tuner and hasattr(tuner, 'preliminary_assess'):
        try:
            res = await maybe_await(tuner.preliminary_assess({'confidence': 0.0, 'factors': []}))
            if isinstance(res, dict):
                factors.extend(list(res.get('factors') or []))
                delta = float(res.get('confidence_adjust') or 0.0)
        except Exception as exc:
            try:
                ctx.logger.debug('Adaptive pre stage error: %s', exc)
            except Exception:
                pass
    return StageResult(name='adaptive_pre', factors=factors, confidence_delta=delta)


@timed_stage('packet_summary')
async def packet_summary_stage(event: dict, ctx: StageContext) -> StageResult:
    try:
        factors = summarize_packet_event(event) or []
    except Exception as exc:
        try:
            ctx.logger.debug('Packet summary stage error: %s', exc)
        except Exception:
            pass
        factors = []
    return StageResult(name='packet_summary', factors=list(factors))
