from __future__ import annotations

import re
import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["NLP"])


def _intent(text: str) -> str:
    t = (text or '').strip().lower()
    if not t:
        return 'help'
    if any(k in t for k in ['maturity','maestro','stride']):
        return 'maturity'
    if any(k in t for k in ['risk','dread']):
        return 'dread'
    if any(k in t for k in ['metric','throughput','ingest','latency','queue']):
        return 'metrics'
    if any(k in t for k in ['alert','incident']):
        return 'alerts'
    if any(k in t for k in ['decision','event','recent']):
        return 'decisions'
    return 'help'

def _parse_time_phrase(text: str) -> float | None:
    """Parse simple phrases like 'last 2 hours', 'last 30 minutes', 'last 1 day'.

    Returns a cutoff epoch seconds if recognized, else None.
    """
    import re, time as _t
    t = (text or '').lower().strip()
    m = re.search(r'last\s+(\d+)\s*(hour|hours|hr|h|minute|minutes|min|m|day|days|d)\b', t)
    if not m:
        return None
    try:
        n = int(m.group(1))
        unit = m.group(2)
        seconds = 0
        if unit in ('hour','hours','hr','h'):
            seconds = n * 3600
        elif unit in ('minute','minutes','min','m'):
            seconds = n * 60
        elif unit in ('day','days','d'):
            seconds = n * 86400
        if seconds > 0:
            return _t.time() - seconds
    except Exception:
        return None
    return None

@router.post('/api/v1/query/nlp')  # type: ignore[misc]
async def nlp_query(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Lightweight NLP router for dashboard queries.

    Accepts: { "text": "...", "context": { optional headers or tenant } }
    Returns: { intent, summary, actions: [{title, path, method}] }
    """
    text = str(payload.get('text') or '')
    intent = _intent(text)
    out: Dict[str, Any] = {
        'intent': intent,
        'timestamp': time.time(),
        'actions': [],
        'summary': {}
    }
    try:
        # Time-range hint: if user asks for last N hours/minutes/days, route alerts with since cutoff
        cutoff = _parse_time_phrase(text)
        if intent == 'maturity':
            out['actions'].append({'title': 'Open Maturity Coverage', 'path': '/api/v1/dashboard/maturity', 'method': 'GET', 'showOnDashboard': True})
            out['summary'] = {'hint': 'Showing MAESTRO and STRIDE coverage counts'}
        elif intent == 'dread':
            out['actions'].append({'title': 'Compute DREAD for selected artifact', 'path': '/api/v1/risk/dread', 'method': 'POST', 'requires': ['factors']})
            out['summary'] = {'hint': 'Provide factors from the current selection to compute DREAD'}
        elif intent == 'metrics':
            out['actions'].append({'title': 'Open Dashboard Metrics', 'path': '/api/v1/dashboard/metrics', 'method': 'GET', 'showOnDashboard': True})
            out['summary'] = {'hint': 'Throughput, detection rate, avg response time'}
        elif intent == 'alerts':
            if cutoff:
                out['actions'].append({'title': 'View Alerts (time filtered)', 'path': f"/api/v1/alerts/recent?limit=50&since={cutoff}", 'method': 'GET', 'showOnDashboard': True})
                out['summary'] = {'hint': 'Recent alerts filtered by time window'}
            else:
                out['actions'].append({'title': 'View Recent Alerts', 'path': '/api/v1/alerts/recent?limit=50', 'method': 'GET', 'showOnDashboard': True})
            out['summary'] = {'hint': 'Recent high-priority alerts'}
        elif intent == 'decisions':
            out['actions'].append({'title': 'View Recent Decisions', 'path': '/api/v1/decisions/recent?limit=50', 'method': 'GET', 'showOnDashboard': True})
            out['summary'] = {'hint': 'Recent classification outputs'}
        else:
            out['actions'] = [
                {'title': 'Maturity Coverage', 'path': '/api/v1/dashboard/maturity', 'method': 'GET'},
                {'title': 'Dashboard Metrics', 'path': '/api/v1/dashboard/metrics', 'method': 'GET'},
                {'title': 'Recent Alerts', 'path': '/api/v1/alerts/recent?limit=50', 'method': 'GET'},
            ]
            out['summary'] = {'hint': 'Try: "maturity", "dread risk", "metrics", "alerts", or "recent decisions"'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return out


__all__ = ['router']
