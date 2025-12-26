from __future__ import annotations

import os

from fastapi import APIRouter, Depends

from db import database as db

from ..dependencies import get_platform_state
from ..state import PlatformState

router = APIRouter()


@router.get('/health', summary='Platform health status')
async def health(state: PlatformState = Depends(get_platform_state)) -> dict:
    db_status = db.get_status()
    cache_state = state.debug_state()
    status = 'ok' if db_status.get('available') else 'degraded'
    if db_status.get('fallback_active'):
        status = 'degraded'
    components = {
        'database': db_status,
        'decision_cache': cache_state,
        'pipeline': {
            'allowlists_enabled': os.getenv('PIPELINE_ALLOWLIST_ENABLED', '1').lower() not in {'0', 'false', 'no'},
        },
    }
    return {
        'status': status,
        'components': components,
    }


@router.get('/internal/debug/state')
def debug_state(state: PlatformState = Depends(get_platform_state)) -> dict:
    return state.debug_state()


# Correlation diagnostics (lightweight introspection)
@router.get('/correlation/state', summary='Correlation module state overview')
def correlation_state() -> dict:
    from src.correlation import CORRELATION_PIPELINE  # type: ignore
    # Import modules conditionally to avoid hard failures if not yet loaded
    out = {'pipeline': CORRELATION_PIPELINE, 'modules': {}}
    # Temporal
    try:
        from src.correlation.temporal import GLOBAL_TEMPORAL_CORRELATOR  # type: ignore
        out['modules']['temporal'] = {
            'window_events': getattr(GLOBAL_TEMPORAL_CORRELATOR, 'total_events', None),
        }
    except Exception:
        pass
    # Co-occurrence
    try:
        from src.correlation.cooccurrence import GLOBAL_COOCCURRENCE_CORRELATOR  # type: ignore
        c = GLOBAL_COOCCURRENCE_CORRELATOR
        out['modules']['cooccurrence'] = {
            'total_events': c.total_events,
            'factor_count': len(c.factor_counts),
            'pair_count': len(c.pair_counts),
            'max_pairs': c.max_pairs,
        }
    except Exception:
        pass
    # Campaigns
    try:
        from src.correlation.campaigns import GLOBAL_CAMPAIGN_CORRELATOR  # type: ignore
        cg = GLOBAL_CAMPAIGN_CORRELATOR
        out['modules']['campaign'] = {
            'pivots': len(cg._pivots),
            'min_incidents': cg.min_incidents,
            'window_seconds': cg.window_seconds,
        }
    except Exception:
        pass
    # Suppression
    try:
        from src.correlation.suppression import GLOBAL_SUPPRESSION_CORRELATOR  # type: ignore
        sp = GLOBAL_SUPPRESSION_CORRELATOR
        out['modules']['suppression'] = {
            'pair_stats': len(sp._stats),
            'min_support': sp.min_support,
            'fp_ratio_threshold': sp.fp_ratio_threshold,
        }
    except Exception:
        pass
    return out
