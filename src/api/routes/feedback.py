from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any
from src.feedback.store import GLOBAL_FEEDBACK_STORE

try:  # metrics optional
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None  # type: ignore
    Histogram = None  # type: ignore

# Metrics (best-effort; reuse label sets to avoid cardinality explosion)
if Counter:
    FEEDBACK_INGEST = Counter('feedback_ingest_total','Total feedback ingested', ['classification'])  # type: ignore
    FEEDBACK_FACTOR_VOTES = Counter('feedback_factor_votes_total','Factor votes (tp/fp) from feedback', ['classification','factor_hash'])  # type: ignore
else:  # pragma: no cover
    FEEDBACK_INGEST = None  # type: ignore
    FEEDBACK_FACTOR_VOTES = None  # type: ignore
if Gauge:
    FEEDBACK_EVENTS_GAUGE = Gauge('feedback_events_total','Distinct events with feedback')  # type: ignore
else:  # pragma: no cover
    FEEDBACK_EVENTS_GAUGE = None  # type: ignore
if Histogram:
    FEEDBACK_PRECISION_HIST = Histogram('feedback_precision_bucket','Distribution of factor precision scores (Laplace-smoothed)')  # type: ignore
else:  # pragma: no cover
    FEEDBACK_PRECISION_HIST = None  # type: ignore

router = APIRouter(prefix='/api/v1/feedback', tags=['feedback'])

class FeedbackIn(BaseModel):  # type: ignore[misc]
    event_id: str = Field(..., min_length=1)
    verdict: str = Field(..., pattern='^(tp|fp|malicious|benign)$')
    comment: Optional[str] = None

def _decision_snapshot(event_id: str) -> tuple[list[dict[str,Any]], dict[str,Any]]:
    """Best-effort fetch of decision factors and meta from DECISION_CACHE.
    Returns (factors_list, decision_meta).
    factors_list entries: {'name','delta','weight'}; delta/weight optional.
    """
    try:
        from src.api.server import DECISION_CACHE  # type: ignore
        dec = DECISION_CACHE.get(event_id)
    except Exception:
        dec = None
    if not dec:
        try:
            from src.api import runtime_state  # type: ignore
            dec = runtime_state.cache_get(event_id)
        except Exception:
            dec = None
    if not dec:
        return [], {}
    # Normalize decision object (dict assumed)
    confidence = dec.get('confidence') if isinstance(dec, dict) else getattr(dec,'confidence', None)
    verdict = dec.get('verdict') if isinstance(dec, dict) else getattr(dec,'verdict', None)
    d_type = dec.get('decision_type') if isinstance(dec, dict) else getattr(dec,'decision_type', None)
    factors_raw = []
    try:
        factors_raw = dec.get('factors') if isinstance(dec, dict) else getattr(dec,'factors', [])
    except Exception:
        factors_raw = []
    factors_list: list[dict[str,Any]] = []
    if isinstance(factors_raw, list):
        for f in factors_raw:
            if isinstance(f, str):
                factors_list.append({'name': f, 'delta': None, 'weight': None})
            elif isinstance(f, dict):
                name = f.get('name') or f.get('factor') or f.get('id')
                if not name:
                    continue
                factors_list.append({'name': name, 'delta': f.get('delta'), 'weight': f.get('weight')})
    return factors_list, {'confidence': confidence, 'verdict': verdict, 'decision_type': d_type}

def _hash_factor(name: str) -> str:
    import hashlib
    return hashlib.sha1(name.encode('utf-8')).hexdigest()[:10]

@router.post('', summary='Submit analyst feedback')  # type: ignore[misc]
def submit_feedback(body: FeedbackIn):
    factors, decision_meta = _decision_snapshot(body.event_id)
    rec = GLOBAL_FEEDBACK_STORE.upsert(body.event_id, body.verdict, factors, decision_meta, body.comment)
    try:
        if FEEDBACK_INGEST:
            FEEDBACK_INGEST.labels(classification=rec['classification']).inc()  # type: ignore
        if FEEDBACK_EVENTS_GAUGE:
            FEEDBACK_EVENTS_GAUGE.set(GLOBAL_FEEDBACK_STORE.stats().get('total_events',0))  # type: ignore
        if FEEDBACK_FACTOR_VOTES and rec['classification'] in {'tp','fp'}:
            for f in rec.get('factors', []):
                nm = f.get('name')
                if not nm:
                    continue
                FEEDBACK_FACTOR_VOTES.labels(classification=rec['classification'], factor_hash=_hash_factor(nm)).inc()  # type: ignore
    except Exception:
        pass
    return {'status':'ok','record': rec}

@router.get('/stats', summary='Feedback aggregate stats')  # type: ignore[misc]
def feedback_stats():
    return GLOBAL_FEEDBACK_STORE.stats()

@router.get('/factors', summary='List factor quality scores')  # type: ignore[misc]
def list_factor_quality(limit: int = 200, sort: str = 'asc'):
    rows = GLOBAL_FEEDBACK_STORE.list_factor_qualities(limit=limit, sort=sort)
    # record histogram samples (best-effort, may be heavy if many factors; limit applied)
    try:
        if FEEDBACK_PRECISION_HIST:
            for r in rows:
                FEEDBACK_PRECISION_HIST.observe(r['score'])  # type: ignore
    except Exception:
        pass
    meta = GLOBAL_FEEDBACK_STORE.quality_metadata()
    return {'factors': rows, 'count': len(rows), **meta}

@router.get('/{event_id}', summary='Fetch feedback for event', operation_id='feedback_get_event')  # type: ignore[misc]
def get_feedback(event_id: str):
    rec = GLOBAL_FEEDBACK_STORE.get(event_id)
    if not rec:
        raise HTTPException(status_code=404, detail='feedback not found')
    return rec


@router.post('/admin/recompute', summary='Admin: Trigger factor quality recompute')  # type: ignore[misc]
def admin_trigger_recompute(payload: dict = {}):
    """Admin endpoint to force a recompute of factor quality scores.

    Expects optional admin auth header in production; in this demo repo it is best-effort.
    """
    try:
        GLOBAL_FEEDBACK_STORE.recompute_quality()
        meta = GLOBAL_FEEDBACK_STORE.quality_metadata()
        return {'status': 'ok', **meta}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'recompute_failed: {exc}')

__all__ = ['router']
