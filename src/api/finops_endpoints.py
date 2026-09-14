from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Request

from core.finops.finops_manager import get_finops_manager

from .runtime_state import get_server_runtime_state

LOGGER = logging.getLogger(__name__)
router = APIRouter()
ARTIFACTS_CONFIG_DIR = Path('artifacts/config')
FINOPS_LIMITS_FILE = ARTIFACTS_CONFIG_DIR / 'finops_limits.json'

def _load_limits_from_disk() -> dict[str, Any] | None:
    try:
        if FINOPS_LIMITS_FILE.exists():
            data = json.loads(FINOPS_LIMITS_FILE.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                return data
    except Exception:
        return None
    return None

def _save_limits_to_disk(limits: dict[str, Any]) -> bool:
    try:
        ARTIFACTS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        FINOPS_LIMITS_FILE.write_text(json.dumps(limits, indent=2), encoding='utf-8')
        return True
    except Exception:
        return False



def _append_jsonl_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, separators=(',', ':')) + '\n')


@router.get('/api/v1/finops/overview', summary='EWMA-based FinOps cost overview')
async def finops_overview(
    request: Request,
    tenant_id: str | None = None,
    alpha: float = 0.3,
    k: float = 3.0,
) -> dict[str, Any]:
    fm = get_finops_manager()
    summary = fm.hourly_summary(tenant_id)
    hours = summary.get('hours', []) if isinstance(summary, dict) else []
    hours.sort(key=lambda row: row.get('hour', 0))
    values = [row.get('cost_units', 0.0) for row in hours]

    result: dict[str, Any] = {
        'tenant': tenant_id or 'all',
        'alpha': alpha,
        'k': k,
        'points': len(values),
    }

    if not values:
        result.update({
            'ewma': None,
            'ewvar': None,
            'ewma_threshold': None,
            'latest_cost': None,
            'anomaly_flag': False,
        })
        return result

    ewma: float | None = None
    ewvar = 0.0
    for value in values:
        if ewma is None:
            ewma = value
            ewvar = 0.0
            continue
        prev = ewma
        ewma = alpha * value + (1 - alpha) * prev
        diff = value - prev
        ewvar = (1 - alpha) * (ewvar + alpha * diff * diff)

    threshold = None if ewma is None else ewma + (k * (ewvar ** 0.5))
    latest = values[-1] if values else None
    anomaly = bool(threshold is not None and latest is not None and latest > threshold)

    result.update({
        'ewma': ewma,
        'ewvar': ewvar,
        'ewma_threshold': threshold,
        'latest_cost': latest,
        'anomaly_flag': anomaly,
    })

    runtime = get_server_runtime_state(request.app)
    try:
        await asyncio.to_thread(
            _append_jsonl_record,
            runtime.finops_anomaly_log,
            {
                'ts': time.time(),
                'tenant': result['tenant'],
                'latest': latest,
                'ewma': ewma,
                'ewvar': ewvar,
                'threshold': threshold,
                'alpha': alpha,
                'k': k,
                'anomaly': anomaly,
            },
        )
    except Exception as exc:
        LOGGER.debug('Failed to append finops anomaly log: %s', exc, exc_info=exc)

    return result


@router.post('/api/v1/finops/budget', summary='Set FinOps budget and limits')
async def finops_set_budget(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {'saved': False, 'error': 'bad_json'}
    monthly = float(body.get('monthly_usd') or 0)
    daily = float(body.get('daily_usd') or 0)
    block = bool(body.get('block_on_exceed') or False)
    per_task = body.get('per_task_caps') or {}
    # Persist minimally in integrations state (consistent with other config in demo)
    try:
        from .integrations_endpoints import _STATE  # type: ignore
        ai = _STATE.setdefault('ai', {'connected': False, 'config': {}, 'last_sync': None, 'error': None})
        cfg = ai.setdefault('config', {})
        limits = cfg.setdefault('limits', {})
        limits['monthly_usd'] = monthly
        limits['daily_usd'] = daily
        limits['block_on_exceed'] = block
        limits['per_task_caps'] = per_task
        ai['connected'] = True
        ai['last_sync'] = time.time()
        # persist to disk for restart resilience
        _save_limits_to_disk(limits)
    except Exception as exc:
        LOGGER.debug('Failed to snapshot limits into integrations state: %s', exc, exc_info=exc)
    return {'saved': True, 'monthly_usd': monthly, 'daily_usd': daily, 'block_on_exceed': block, 'per_task_caps': per_task}


__all__ = ['router', 'finops_overview']

# Load persisted limits into integrations state at import time (best effort)
try:
    from .integrations_endpoints import _STATE  # type: ignore
    limits = _load_limits_from_disk()
    if limits:
        ai = _STATE.setdefault('ai', {'connected': False, 'config': {}, 'last_sync': None, 'error': None})
        cfg = ai.setdefault('config', {})
        cfg['limits'] = limits
        ai['connected'] = True
        ai['last_sync'] = time.time()
except Exception as exc:
    LOGGER.debug('Failed to load FinOps limits from disk: %s', exc)


# Per-tenant Tier2 budget caps via tenant_overrides
@router.get('/api/v1/finops/tenant_budget', summary='Get per-tenant Tier2 budget caps')
async def finops_get_tenant_budget(tenant_id: str | None = None) -> dict[str, Any]:
    tid = tenant_id or 'default'
    try:
        from src.core.config.tenant_overrides import get_overrides  # type: ignore
        ov = get_overrides(tid) or {}
    except Exception:
        ov = {}
    return {
        'tenant': tid,
        'tier2_budget_left': float(ov.get('tier2_budget_left', ov.get('t2_budget_left', 9999.0) or 9999.0)),
    }


@router.post('/api/v1/finops/tenant_budget', summary='Set per-tenant Tier2 budget caps')
async def finops_set_tenant_budget(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {'saved': False, 'error': 'bad_json'}
    tid = str(body.get('tenant') or body.get('tenant_id') or 'default')
    try:
        budget = float(body.get('tier2_budget_left') or body.get('t2_budget_left'))
    except Exception:
        return {'saved': False, 'error': 'invalid_budget'}
    if budget < 0:
        return {'saved': False, 'error': 'invalid_budget'}
    try:
        from src.core.config.tenant_overrides import upsert_overrides  # type: ignore
        upsert_overrides(tid, {'tier2_budget_left': budget})
    except Exception:
        return {'saved': False, 'error': 'persist_failed'}
    return {'saved': True, 'tenant': tid, 'tier2_budget_left': budget}
