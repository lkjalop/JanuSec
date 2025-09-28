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
