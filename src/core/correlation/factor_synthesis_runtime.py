"""Shared runtime helpers for FactorSynthesisEngine configuration/loading."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

from src.core.correlation.factor_synthesis import (
    FactorCategory,
    FactorSynthesisEngine,
)
from src.core.quality.factor_telemetry import load_factor_telemetry

try:  # pragma: no cover - optional quality manager
    from src.core.quality.factor_quality import get_quality_manager  # type: ignore
except Exception:  # pragma: no cover
    get_quality_manager = None  # type: ignore

# Cached engine + config signature so callers reuse a single instance.
_ENGINE: FactorSynthesisEngine | None = None
_SIGNATURE: str | None = None

# Base config cache (to avoid re-reading file on every call).
_BASE_CACHE: dict[str, Any] | None = None
_BASE_PATH: str | None = None
_BASE_MTIME: float | None = None


def factor_category_for_name(name: str) -> FactorCategory:
    """Map a factor prefix to FactorCategory."""
    prefix = (name or '').split(':', 1)[0].lower()
    mapping = {
        'endpoint': FactorCategory.ENDPOINT,
        'process': FactorCategory.ENDPOINT,
        'net': FactorCategory.NETWORK,
        'network': FactorCategory.NETWORK,
        'dns': FactorCategory.NETWORK,
        'email': FactorCategory.EMAIL,
        'identity': FactorCategory.IDENTITY,
        'iam': FactorCategory.IDENTITY,
        'cloud': FactorCategory.CLOUD,
        'data': FactorCategory.DATA,
        'remote': FactorCategory.REMOTE_ACCESS,
        'rdp': FactorCategory.REMOTE_ACCESS,
        'vpn': FactorCategory.REMOTE_ACCESS,
        'api': FactorCategory.API,
        'app': FactorCategory.API,
    }
    return mapping.get(prefix, FactorCategory.META)


def _load_base_config() -> dict[str, Any]:
    """Load base synthesis JSON config with caching."""
    global _BASE_CACHE, _BASE_PATH, _BASE_MTIME
    path = os.getenv('FACTOR_SYNTHESIS_CONFIG', 'config/factor_synthesis.json') or ''
    try:
        stat = os.stat(path)
        mtime = getattr(stat, 'st_mtime', None)
    except Exception:
        _BASE_CACHE = {}
        _BASE_PATH = path
        _BASE_MTIME = None
        return {}
    if (
        _BASE_CACHE is not None
        and _BASE_PATH == path
        and _BASE_MTIME == mtime
    ):
        return dict(_BASE_CACHE)
    try:
        with open(path, encoding='utf-8') as fh:
            cfg = json.load(fh) or {}
    except Exception:
        cfg = {}
    _BASE_CACHE = dict(cfg)
    _BASE_PATH = path
    _BASE_MTIME = mtime
    return dict(cfg)


def _build_config() -> dict[str, Any]:
    """Merge base config with live FP/context data when available."""
    base = _load_base_config()
    telemetry = load_factor_telemetry()
    if telemetry:
        if telemetry.get('factor_fp_stats'):
            merged_fp = dict(base.get('factor_fp_stats') or {})
            merged_fp.update(telemetry.get('factor_fp_stats') or {})
            base['factor_fp_stats'] = merged_fp
        history_rows = telemetry.get('factor_history')
        if history_rows:
            base['factor_history'] = history_rows
            merged_fp = dict(base.get('factor_fp_stats') or {})
            for row in history_rows:
                name = (row or {}).get('factor')
                rate = (row or {}).get('fp_rate')
                if not name or rate is None:
                    continue
                key = str(name).lower()
                merged_fp.setdefault(key, {'fp_rate': float(rate)})
            base['factor_fp_stats'] = merged_fp
        if telemetry.get('context_multipliers'):
            merged_ctx = dict(base.get('context_multipliers') or {})
            merged_ctx.update(telemetry.get('context_multipliers') or {})
            base['context_multipliers'] = merged_ctx
        base.setdefault('telemetry_meta', {})
        base['telemetry_meta'].update({
            'timestamp': telemetry.get('timestamp'),
            'window_precision': telemetry.get('window_precision'),
            'window_counts': telemetry.get('window_counts'),
            'suppressed': telemetry.get('suppressed'),
        })
    if get_quality_manager:
        try:
            quality = get_quality_manager()
        except Exception:
            quality = None
        if quality is not None:
            fp_stats = quality.export_fp_rates()
            if fp_stats:
                base['factor_fp_stats'] = fp_stats
            ctx = quality.get_context_multipliers()
            if ctx:
                merged_ctx = dict(base.get('context_multipliers') or {})
                merged_ctx.update(ctx)
                base['context_multipliers'] = merged_ctx
    return base


def get_factor_synthesis_engine() -> FactorSynthesisEngine | None:
    """Return (and cache) a configured FactorSynthesisEngine instance."""
    global _ENGINE, _SIGNATURE
    try:
        config = _build_config()
        signature = json.dumps(config, sort_keys=True)
    except Exception:
        config = {}
        signature = None
    if _ENGINE is None or signature != _SIGNATURE:
        try:
            _ENGINE = FactorSynthesisEngine(config=config if config else None)
            _SIGNATURE = signature
        except Exception:
            _ENGINE = None
            _SIGNATURE = None
    return _ENGINE


__all__ = ['get_factor_synthesis_engine', 'factor_category_for_name']
