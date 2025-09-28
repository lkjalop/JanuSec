from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List

from core.detect.beacon_analyzer import get_beacon_analyzer
from core.detect.domain_tracker import get_domain_tracker
from core.detect.egress_tracker import get_egress_tracker
from core.detect.rare_token_detector import get_rare_token_model

from ..utils import cfg_get
from .base import StageContext, StageResult, timed_stage

try:  # pragma: no cover - optional metrics dependency
    from prometheus_client import Counter as _PromCounter  # type: ignore

    _egress_spike_counter = _PromCounter(
        'egress_volume_spike_total',
        'Detected outbound egress volume spikes',
        ['tenant']
    )
    _domain_novelty_counter = _PromCounter(
        'domain_novelty_total',
        'New or rare domains observed within novelty window',
        ['tenant']
    )
except Exception:  # pragma: no cover
    class _CounterStub:
        def labels(self, *_, **__):
            return self

        def inc(self, *_, **__):
            return None

    _egress_spike_counter = _CounterStub()
    _domain_novelty_counter = _CounterStub()


@timed_stage('beacon')
async def beacon_stage(event: dict, ctx: StageContext) -> StageResult:
    factors: List[str] = []
    try:
        dst_ip = event.get('dst_ip') or event.get('destination_ip')
        dst_port = event.get('dst_port') or event.get('destination_port')
        if dst_ip and isinstance(dst_port, int):
            factors.extend(get_beacon_analyzer().observe(dst_ip, dst_port) or [])
    except Exception as exc:
        try:
            ctx.logger.debug('Beacon stage error: %s', exc)
        except Exception:
            pass
    return StageResult(name='beacon', factors=factors)


@timed_stage('egress')
async def egress_stage(event: dict, ctx: StageContext) -> StageResult:
    host = event.get('host_id') or event.get('src_host')
    bytes_out = event.get('bytes_out') or event.get('out_bytes')
    if not host or not isinstance(bytes_out, (int, float)):
        return StageResult(name='egress', factors=[])

    tenant = event.get('tenant_id') or 'default'
    spike = False
    try:
        tracker = get_egress_tracker()
        spike = bool(tracker.observe(tenant, host, float(bytes_out)))
    except Exception as exc:
        try:
            ctx.logger.debug('Egress tracker error: %s', exc)
        except Exception:
            pass

    history_store: Dict[str, Deque[float]] = ctx.state.setdefault('egress_history_store', {})  # type: ignore[assignment]
    key = f"{tenant}::{host}"
    if key not in history_store:
        history_store[key] = deque(maxlen=10)
    history = history_store[key]
    baseline = sum(history) / len(history) if history else 0.0
    history.append(float(bytes_out))

    if not spike and baseline > 0:
        pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
        egress_cfg = cfg_get(pipeline_cfg, 'egress', {})
        ratio_threshold = float(cfg_get(egress_cfg, 'fallback_ratio', 8.0) or 8.0)
        absolute_threshold = float(cfg_get(egress_cfg, 'min_bytes', 0) or 0)
        if bytes_out >= absolute_threshold and bytes_out >= baseline * ratio_threshold:
            spike = True

    factors = ['egress_volume_spike'] if spike else []
    if spike:
        try:
            _egress_spike_counter.labels(tenant=tenant).inc()
        except Exception:  # pragma: no cover
            pass
    return StageResult(name='egress', factors=factors)


@timed_stage('domain_novelty')
async def domain_novelty_stage(event: dict, ctx: StageContext) -> StageResult:
    domain = event.get('domain') or event.get('dst_domain') or event.get('fqdn')
    tenant = event.get('tenant_id') or 'default'
    factors: List[str] = []
    if isinstance(domain, str) and domain:
        try:
            if get_domain_tracker().observe(tenant, domain):
                factors.append('new_domain_seen')
                try:
                    _domain_novelty_counter.labels(tenant=tenant).inc()
                except Exception:  # pragma: no cover
                    pass
        except Exception as exc:
            try:
                ctx.logger.debug('Domain novelty error: %s', exc)
            except Exception:
                pass
    return StageResult(name='domain_novelty', factors=factors)


@timed_stage('rare_token')
async def rare_token_stage(event: dict, ctx: StageContext) -> StageResult:
    cmd = event.get('cmdline') or event.get('command_line') or ''
    tenant = event.get('tenant_id') or 'default'
    factors: List[str] = []
    if isinstance(cmd, str) and len(cmd) > 6:
        try:
            stats = get_rare_token_model().observe(tenant, cmd)
            ratio = float(stats.get('rare_ratio', 0.0) or 0.0)
            if ratio > 0:
                factors.append(f'cmd_rare_token_ratio:{ratio:.3f}')
            if ratio >= 0.4 and stats.get('token_count', 0) >= 4 and stats.get('rare_count', 0) >= 2:
                factors.append('cmd_rare_token_spike')
        except Exception as exc:
            try:
                ctx.logger.debug('Rare token stage error: %s', exc)
            except Exception:
                pass
    return StageResult(name='rare_token', factors=factors)
