from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List

from core.detect.beacon_analyzer import get_beacon_analyzer
from core.detect.domain_tracker import get_domain_tracker
from core.detect.egress_tracker import get_egress_tracker
from core.detect.rare_token_detector import get_rare_token_model

from ..utils import cfg_get
from .base import StageContext, StageResult, timed_stage

# Lightweight streaming sketches and detectors (optional availability)
try:  # pragma: no cover - optional dependency wiring
    from metrics.streaming import (
        CMS_DEFAULT as _CMS,
        HLL_DEFAULT as _HLL,
        BLOOM_BENIGN as _BLOOM,
        HW_DEFAULT as _HW,
        CUSUM_DEFAULT as _CUSUM,
        RARITY_DAILY as _RARITY,
    )
except Exception:  # pragma: no cover
    _CMS = _HLL = _BLOOM = _HW = _CUSUM = _RARITY = None  # type: ignore

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
    factors: list[str] = []
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

    history_store: dict[str, deque[float]] = ctx.state.setdefault('egress_history_store', {})  # type: ignore[assignment]
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

    # Streaming change detection (Holt-Winters residual and CUSUM)
    try:
        key_hw = f"{tenant}::{host}::egress"
        # Allow residual z-threshold override via pipeline config
        pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
        egress_cfg = cfg_get(pipeline_cfg, 'egress', {})
        try:
            z_thr = float(cfg_get(egress_cfg, 'residual_z', 3.0) or 3.0)
        except Exception:
            z_thr = 3.0
        if _HW is not None:
            res = _HW.update(key_hw, float(bytes_out))
            z = float(res.get('z') or 0.0)
            if z >= z_thr:
                factors.append('an:egress_residual_spike')
                factors.append(f"z:egress:{z:.2f}")
        if _CUSUM is not None and baseline > 0:
            try:
                ratio = float(bytes_out) / float(baseline)
                # Cap extreme ratios to stabilize CUSUM
                ratio = max(0.0, min(ratio, 100.0))
                out = _CUSUM.update(key_hw, ratio)
                if bool(out.get('alarm')):
                    factors.append('chg:egress_burst')
            except Exception:
                pass
    except Exception:
        pass
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
    factors: list[str] = []
    if isinstance(domain, str) and domain:
        try:
            # Optional benign suppression via Bloom for configured suffixes
            try:
                import os
                suffixes = (os.getenv('BLOOM_BENIGN_DOMAINS','') or '').split(',')
                suffixes = [s.strip().lower() for s in suffixes if s.strip()]
                if suffixes and any(domain.lower().endswith(suf) for suf in suffixes):
                    if _BLOOM is not None:
                        _BLOOM.add(f"{tenant}::{domain}")
                    return StageResult(name='domain_novelty', factors=[])
            except Exception:
                pass

            # Wire sketches for rates and distinct counts
            try:
                if _CMS is not None:
                    _CMS.add(f"{tenant}::domain::{domain}")
                if _HLL is not None:
                    _HLL.add(f"{tenant}::domain::{domain}")
            except Exception:
                pass

            if get_domain_tracker().observe(tenant, domain):
                factors.append('new_domain_seen')
                try:
                    _domain_novelty_counter.labels(tenant=tenant).inc()
                except Exception:  # pragma: no cover
                    pass
            # Rolling rarity (first-seen within TTL)
            try:
                if _RARITY is not None and _RARITY.update(f"{tenant}::domain::{domain}"):
                    factors.append('rare:domain_tenant')
            except Exception:
                pass
            # User-Agent rarity (if present)
            try:
                ua = event.get('user_agent') or event.get('ua')
                if isinstance(ua, str) and ua and _RARITY is not None and _RARITY.update(f"{tenant}::ua::{ua}"):
                    factors.append('rare:useragent_tenant')
            except Exception:
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
    factors: list[str] = []
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


# ---------------------------------------------------------------------------
# NetworkMLPipeline stage — beacon, exfil, DGA, C2, tunnel ML detectors
# Lazy singleton: loaded on first use, silently skipped when unavailable.
# ---------------------------------------------------------------------------
_network_ml_pipeline = None
_network_ml_tried = False


def _get_network_ml_pipeline():
    global _network_ml_pipeline, _network_ml_tried
    if not _network_ml_tried:
        _network_ml_tried = True
        try:
            from src.ml.network_ml_pipeline import NetworkMLPipeline  # type: ignore
            _network_ml_pipeline = NetworkMLPipeline()
        except Exception:
            _network_ml_pipeline = None
    return _network_ml_pipeline


@timed_stage('network_ml')
async def network_ml_stage(event: dict, ctx: StageContext) -> StageResult:
    """Run NetworkMLPipeline beacon/exfil/DGA/C2-tunnel detectors on each flow event."""
    factors: list[str] = []
    pipeline = _get_network_ml_pipeline()
    if pipeline is None:
        return StageResult(name='network_ml', factors=factors)
    try:
        flow = {
            'src_ip': event.get('src_ip') or event.get('source_ip') or '',
            'dst_ip': event.get('dst_ip') or event.get('destination_ip') or '',
            'dst_port': event.get('dst_port') or event.get('destination_port') or 0,
            'proto': event.get('proto') or event.get('protocol') or '',
            'bytes_out': event.get('bytes_out') or event.get('out_bytes') or 0,
            'bytes_in': event.get('bytes_in') or event.get('in_bytes') or 0,
            'duration': event.get('duration') or event.get('conn_duration') or 0.0,
            'domain': event.get('domain') or event.get('fqdn') or event.get('dst_domain') or '',
            'ja3': event.get('ja3') or '',
            'ja3s': event.get('ja3s') or '',
        }
        ml_result = pipeline.run_flow(flow)
        for fac in (ml_result.get('factors') or []):
            if isinstance(fac, str):
                factors.append(fac)
            elif isinstance(fac, dict):
                fname = fac.get('factor') or fac.get('name') or ''
                if fname:
                    factors.append(fname)
    except Exception as exc:
        try:
            ctx.logger.debug('network_ml stage error: %s', exc)
        except Exception:
            pass
    return StageResult(name='network_ml', factors=factors)
