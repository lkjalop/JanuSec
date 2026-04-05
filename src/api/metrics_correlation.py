from __future__ import annotations
from fastapi import APIRouter
from src.core.correlation.simple_metrics import get_metrics_snapshot
from fastapi.responses import Response
import os

try:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST  # type: ignore
except Exception:
    # Fallback to metrics_init's generate_latest shim
    try:
        from src.api.metrics_init import _generate_latest_fallback_top as generate_latest  # type: ignore
        CONTENT_TYPE_LATEST = 'text/plain; version=0.0.4; charset=utf-8'
    except Exception:
        generate_latest = lambda *a, **k: b''  # type: ignore
        CONTENT_TYPE_LATEST = 'text/plain; version=0.0.4; charset=utf-8'

router = APIRouter(prefix='/api/v1/metrics', tags=['metrics'])


@router.get('/correlation')
def correlation_metrics():
    """Return a lightweight snapshot for correlation rule metrics."""
    return get_metrics_snapshot()


@router.get('/prometheus')
def prometheus_metrics():
    """Return Prometheus exposition format for scraping.

    Uses the installed `prometheus_client.generate_latest` when available,
    otherwise falls back to a deterministic shim provided by `metrics_init`.
    """
    try:
        # If a REGISTRY exists, most generate_latest implementations accept an
        # optional registry argument; prefer to call without to let the
        # underlying module decide.
        body = generate_latest()
    except TypeError:
        try:
            # some fallbacks require the REGISTRY to be passed
            from src.api.metrics_init import REGISTRY  # type: ignore
            body = generate_latest(REGISTRY)  # type: ignore
        except Exception:
            body = b''
    except Exception:
        body = b''
    return Response(content=body or b'', media_type=CONTENT_TYPE_LATEST)
