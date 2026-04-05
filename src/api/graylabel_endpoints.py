from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/graylabel", tags=["graylabel"])

_SINK_PATH = Path(os.getenv('GRAYLABEL_SINK_PATH', 'data/gray_tier_events.jsonl'))


@router.post('/sink')
async def graylabel_sink(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Persist borderline (gray-tier) events for evaluation.

    Accepts arbitrary JSON; when 'severity' is included and within [0.45, 0.60],
    writes to JSONL sink (path set by GRAYLABEL_SINK_PATH). If severity missing,
    accepts but writes with severity=null.
    """
    try:
        sev = payload.get('severity')
        borderline = False
        try:
            if isinstance(sev, (int, float)):
                borderline = (0.45 <= float(sev) <= 0.60)
        except Exception:
            borderline = False
        # ensure directory exists
        try:
            _SINK_PATH.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        line = json.dumps({**payload, '__borderline__': borderline}, ensure_ascii=False)
        with _SINK_PATH.open('a', encoding='utf-8') as f:
            f.write(line + "\n")
        return {'status': 'ok', 'borderline': borderline, 'path': str(_SINK_PATH)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'gray sink failed: {exc}')


@router.get('/stats')
async def graylabel_stats(limit: int = 200) -> Dict[str, Any]:
    """Return a simple tail of the sink for quick validation."""
    if not _SINK_PATH.exists():
        return {'count': 0, 'items': []}
    try:
        lines = _SINK_PATH.read_text(encoding='utf-8').splitlines()
        items = [json.loads(x) for x in lines[-limit:]]
        return {'count': len(lines), 'items': items}
    except Exception:
        return {'count': 0, 'items': []}

