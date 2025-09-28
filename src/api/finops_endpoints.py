from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Request

from src.core.finops.finops_manager import get_finops_manager

from .runtime_state import get_server_runtime_state

LOGGER = logging.getLogger(__name__)
router = APIRouter()


def _append_jsonl_record(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, separators=(',', ':')) + '\n')


@router.get('/api/v1/finops/overview', summary='EWMA-based FinOps cost overview')
async def finops_overview(
    request: Request,
    tenant_id: str | None = None,
    alpha: float = 0.3,
    k: float = 3.0,
) -> Dict[str, Any]:
    fm = get_finops_manager()
    summary = fm.hourly_summary(tenant_id)
    hours = summary.get('hours', []) if isinstance(summary, dict) else []
    hours.sort(key=lambda row: row.get('hour', 0))
    values = [row.get('cost_units', 0.0) for row in hours]

    result: Dict[str, Any] = {
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

    ewma: Optional[float] = None
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


__all__ = ['router', 'finops_overview']
