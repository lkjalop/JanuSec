from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix='/api/v1/fetch', tags=['OnDemandFetch'])

# Optional Zeek adapter
try:
    from src.live.zeek_adapter import parse_zeek_line  # type: ignore
except Exception:  # pragma: no cover - lite fallback
    try:
        from live.zeek_adapter import parse_zeek_line  # type: ignore
    except Exception:
        parse_zeek_line = None  # type: ignore

class TimeWindow(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None
    last: Optional[str] = None

class FetchFilters(BaseModel):
    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    process: Optional[str] = None

class FetchRequest(BaseModel):
    source: str = Field(..., description='zeek|suricata|sysmon|etw')
    kind: Optional[str] = Field(None, description='For Zeek, e.g., dns|http|ssl|conn')
    lines: Optional[List[str]] = Field(default=None, description='Optional JSONL content to parse directly')
    time_window: Optional[TimeWindow] = None
    filters: Optional[FetchFilters] = None
    limit: Optional[int] = Field(default=500, description='Maximum events to process')


def _ensure_session(events: List[Dict[str, Any]] | None, label: str, filters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    sid = f"batch-{label}"
    data = {
        'id': sid,
        'data': {
            'entities': {
                'user': filters.get('user'),
                'host': filters.get('host'),
                'ip': filters.get('ip'),
                'domain': filters.get('domain'),
                'file_hash': filters.get('file_hash'),
                'process': filters.get('process'),
            },
            'events': events or [],
        }
    }
    return sid, data


def build_session_from_lines(source: str, kind: Optional[str], lines: List[str] | None, filters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    src = (source or '').lower()
    events: List[Dict[str, Any]] = []
    if lines:
        if src == 'zeek' and parse_zeek_line is not None:
            for ln in lines:
                try:
                    ev = parse_zeek_line(kind or '', ln)
                    if ev: events.append(ev)
                except Exception:
                    continue
        else:
            # Generic passthrough for suricata/sysmon/etw (assume JSONL-like rows)
            import json
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    if isinstance(obj, dict):
                        events.append(obj)
                except Exception:
                    continue
    # Minimal session wrapper
    return _ensure_session(events, f"{src}-{kind or 'generic'}", filters)


@router.post('/lines')
async def fetch_from_lines(req: FetchRequest) -> Dict[str, Any]:
    try:
        filters = (req.filters.model_dump() if req.filters else {})
    except Exception:
        filters = {}
    sid, session = build_session_from_lines(req.source, req.kind, req.lines or [], filters)
    return {'session_id': sid, 'session': session}


def _synthetic_event(source: str, i: int, filters: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal normalized shape for demo
    obj = {
        'source': source,
        'ts': __import__('time').time(),
        'event_id': f'{source}-{i}',
        'user': filters.get('user'),
        'host': filters.get('host'),
        'ip': filters.get('ip'),
        'domain': filters.get('domain'),
        'file_hash': filters.get('file_hash'),
        'process': filters.get('process'),
    }
    # add source-specific hints
    if source == 'zeek':
        obj['proto'] = 'tcp'
    elif source == 'suricata':
        obj['alert'] = {'severity': 2, 'signature': 'DEMO-SIGNATURE'}
    elif source == 'sysmon':
        obj['event'] = {'id': 1, 'name': 'ProcessCreate'}
    elif source == 'etw':
        obj['provider'] = 'Microsoft-Windows-Kernel-Process'
    return obj


def build_session_from_source(source: str, filters: Dict[str, Any], time_window: Optional[TimeWindow], kind: Optional[str], limit: int = 250) -> Tuple[str, Dict[str, Any]]:
    src = (source or '').lower()
    events: List[Dict[str, Any]] = []
    # TODO: Plug in real adapters or data sources
    # For now, produce synthetic events constrained by filters
    n = max(3, min(limit, 50))
    for i in range(n):
        events.append(_synthetic_event(src, i, filters))
    return _ensure_session(events, f"{src}-{kind or 'generic'}", filters)


@router.post('/zeek')
async def fetch_zeek(req: FetchRequest) -> Dict[str, Any]:
    filters = (req.filters.model_dump() if req.filters else {})
    sid, session = build_session_from_source('zeek', filters, req.time_window, req.kind, req.limit or 250)
    return {'session_id': sid, 'session': session}

@router.post('/suricata')
async def fetch_suricata(req: FetchRequest) -> Dict[str, Any]:
    filters = (req.filters.model_dump() if req.filters else {})
    sid, session = build_session_from_source('suricata', filters, req.time_window, req.kind, req.limit or 250)
    return {'session_id': sid, 'session': session}

@router.post('/sysmon')
async def fetch_sysmon(req: FetchRequest) -> Dict[str, Any]:
    filters = (req.filters.model_dump() if req.filters else {})
    sid, session = build_session_from_source('sysmon', filters, req.time_window, req.kind, req.limit or 250)
    return {'session_id': sid, 'session': session}

@router.post('/etw')
async def fetch_etw(req: FetchRequest) -> Dict[str, Any]:
    filters = (req.filters.model_dump() if req.filters else {})
    sid, session = build_session_from_source('etw', filters, req.time_window, req.kind, req.limit or 250)
    return {'session_id': sid, 'session': session}

__all__ = ['router', 'build_session_from_lines']
