"""Lightweight metrics endpoints for correlation rules and Prometheus exposition.

Exposes:
  GET /api/v1/metrics/correlation  — rule fire counts, FP/TP ratios, Prometheus status
  GET /api/v1/metrics/prometheus   — raw Prometheus text format (or empty if unavailable)
"""
from __future__ import annotations

import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter(tags=['metrics'])


@router.get('/api/v1/metrics/correlation')
async def metrics_correlation():
    """Return correlation rule metrics plus Prometheus availability flag."""
    try:
        from src.core.correlation.rules.registry import CORRELATION_RULES
        rule_metrics = CORRELATION_RULES.get_metrics()
    except Exception:
        rule_metrics = {}

    try:
        from prometheus_client import REGISTRY, generate_latest
        from prometheus_client.exposition import choose_encoder
        prometheus_enabled = True
    except Exception:
        prometheus_enabled = False

    return JSONResponse({
        'prometheus_enabled': prometheus_enabled,
        'counters': rule_metrics,
    })


@router.get('/api/v1/metrics/prometheus')
async def metrics_prometheus():
    """Expose Prometheus metrics in text format."""
    try:
        from prometheus_client import generate_latest, REGISTRY
        text = generate_latest(REGISTRY)
        return PlainTextResponse(text.decode('utf-8') if isinstance(text, bytes) else text)
    except Exception:
        # Fallback: return custom metrics from REGISTRY._dummy_samples if available
        try:
            from src.api.metrics_init import REGISTRY as LOCAL_REGISTRY
            samples = getattr(LOCAL_REGISTRY, '_dummy_samples', {}) or {}
            lines = []
            for name, entries in samples.items():
                lines.append(f'# TYPE {name} counter')
                for entry in entries:
                    label_str = ','.join(f'{k}="{v}"' for k, v in (entry.labels or {}).items())
                    lines.append(f'{name}{{{label_str}}} {entry.value}')
            return PlainTextResponse('\n'.join(lines) + '\n')
        except Exception:
            return PlainTextResponse('')
