from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api/v1/data", tags=["data"])
_COUNTS = {'ingest_total': 0, 'pii_query': 0, 'large_result_set': 0, 'unusual_sink': 0}


class DataAccessIn(BaseModel):
    user: str
    database: str
    table: str
    query: Optional[str] = None
    record_count: Optional[int] = Field(None, description="Estimated rows returned")
    sink: Optional[str] = Field(None, description="Export target (e.g., s3://bucket/key)")
    timestamp: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


@router.post('/ingest')
async def ingest_data_access(event: DataAccessIn, request: Request) -> Dict[str, Any]:
    app = request.app
    # Prefer app.GLOBAL_HOPGRAPH; fall back to app.state.hopgraph; lazily create in TEST_HELPERS
    try:
        hopgraph = getattr(app, 'GLOBAL_HOPGRAPH', None)
        if hopgraph is None:
            hopgraph = getattr(getattr(app, 'state', object()), 'hopgraph', None)
    except Exception:
        hopgraph = None
    try:
        import os as _os
        if hopgraph is None and (_os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'} or _os.getenv('JANUSEC_TEST_MODE','0').lower() in {'1','true','yes'}):
            try:
                from src.graph.hopgraph import HopGraph as _HG  # type: ignore
            except Exception:
                from core.graph.hopgraph import HopGraph as _HG  # type: ignore
            hopgraph = _HG()
            try:
                setattr(app, 'GLOBAL_HOPGRAPH', hopgraph)
                if hasattr(app, 'state'):
                    setattr(app.state, 'hopgraph', hopgraph)  # type: ignore[attr-defined]
            except Exception:
                pass
    except Exception:
        pass
    try:
        from src.core.graph.data_hopgraph import DataAccessEvent, ingest_to_hopgraph
    except Exception:
        from core.graph.data_hopgraph import DataAccessEvent, ingest_to_hopgraph

    ev = DataAccessEvent(
        user=event.user,
        database=event.database,
        table=event.table,
        query=event.query,
        record_count=event.record_count,
        sink=event.sink,
        timestamp=event.timestamp,
        raw=event.raw or {},
    )
    try:
        res = ingest_to_hopgraph(ev, hopgraph)
        try:
            _COUNTS['ingest_total'] += 1
            sig = ((res or {}).get('result') or {}).get('signals') if False else None  # placeholder if res echoed signals
        except Exception:
            pass
        # Best-effort: detect large data extracts from record_count or sink
        try:
            from src.core.detectors.data_large_extract import check_and_emit as check_data_large
        except Exception:
            check_data_large = None
        try:
            # If record_count large, use user node as source
            if check_data_large and (ev.record_count and ev.record_count >= 10000):
                src_node = f'user:{ev.user}'
                # estimate bytes_out conservatively as record_count * 1000
                bytes_est = int(ev.record_count) * 1000
                check_data_large(hopgraph, src_node, bytes_est)
            # If sink looks like external export, also call with a larger heuristic
            if check_data_large and ev.sink and ('s3://' in (ev.sink or '').lower() or (ev.sink or '').lower().startswith('http')):
                src_node = f'user:{ev.user}'
                check_data_large(hopgraph, src_node, 5_000_000)
        except Exception:
            pass
        # Best effort: infer signals from query/record_count/sink
        try:
            if ev.query and any(x in ev.query.lower() for x in ('ssn','credit','card','pii')):
                _COUNTS['pii_query'] += 1
            if (ev.record_count or 0) >= 10000:
                _COUNTS['large_result_set'] += 1
            if ev.sink and (ev.sink.lower().startswith('http') or ('s3://' in ev.sink.lower())):
                _COUNTS['unusual_sink'] += 1
        except Exception:
            pass
        return {'status': 'accepted', 'result': res}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'failed: {exc}')


@router.get('/summary')
async def data_summary() -> Dict[str, Any]:
    return {'counts': dict(_COUNTS)}
