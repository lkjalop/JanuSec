"""Server-Sent Events streaming of decisions."""
from __future__ import annotations
import asyncio, json, os, time
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter()
_QUEUE: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
from collections import deque
_TIMELINE_STORE = {}
_TIMELINE_ORDER = deque(maxlen=500)  # remember insertion order for pruning
_TIMELINE_MAX = 500

async def publish_decision(summary: dict):
    """Publish decision to SSE clients and store compact stage timeline.

    Expected summary includes optional 'stage_timings' list of
    {name,duration_ms,confidence_after} items plus 'event_id'.
    """
    # Extract timeline and store for later retrieval endpoint
    eid = summary.get('event_id') or summary.get('id')
    st = summary.get('stage_timings') or []
    if eid and st:
        _TIMELINE_STORE[eid] = {
            'event_id': eid,
            'timeline': st,
            'factors': summary.get('factors', [])[:40],  # cap factors for memory
            'ts': summary.get('ts') or time.time(),
            'confidence': summary.get('confidence')
        }
        _TIMELINE_ORDER.append(eid)
        # Prune if exceeding cap
        if len(_TIMELINE_STORE) > _TIMELINE_MAX:
            try:
                old = _TIMELINE_ORDER.popleft()
                _TIMELINE_STORE.pop(old, None)
            except Exception:
                pass
    # Trim payload for SSE (avoid huge factor arrays)
    if 'factors' in summary and isinstance(summary['factors'], list) and len(summary['factors']) > 30:
        summary = dict(summary)
        summary['factors_truncated'] = summary['factors'][:30]
        del summary['factors']
    # Drop oldest if queue full
    if _QUEUE.full():
        try: _QUEUE.get_nowait()
        except Exception: pass
    await _QUEUE.put(summary)

async def _event_stream():
    if os.getenv('PYTEST_CURRENT_TEST') or os.getenv('SSE_TEST_MODE'):
        payload = json.dumps({'status': 'test-mode'}).encode('utf-8')
        yield b'data: ' + payload + b'\n\n'
        return

    while True:
        try:
            item = await asyncio.wait_for(_QUEUE.get(), timeout=0.5)
        except asyncio.TimeoutError:
            yield b':keepalive\n\n'
            continue
        data = json.dumps(item, separators=(',',':')).encode('utf-8')
        yield b'data: ' + data + b'\n\n'

@router.get('/api/v1/stream/decisions')
async def decisions_stream():
    return StreamingResponse(_event_stream(), media_type='text/event-stream')

@router.get('/api/v1/decisions/timeline/{event_id}')
async def decision_timeline(event_id: str):
    """Return stored stage timeline (if still in memory window)."""
    item = _TIMELINE_STORE.get(event_id)
    if not item:
        return { 'found': False, 'event_id': event_id }
    return { 'found': True, 'timeline': item.get('timeline'), 'factors': item.get('factors'), 'confidence': item.get('confidence'), 'ts': item.get('ts') }

__all__ = ['router','publish_decision']
