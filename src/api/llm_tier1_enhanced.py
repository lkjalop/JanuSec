from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any
from src.repositories.llm_claims_repo import record_claim
from fastapi import Body
from src.repositories.llm_claims_repo import mark_adjudication, list_unadjudicated, stats as claims_stats

router = APIRouter(prefix='/api/v1/llm/tier1', tags=['llm'])


class Tier1EnhancedRequest(BaseModel):
    decision_id: str
    top_factors: List[Dict[str, Any]]
    related_events: List[Dict[str, Any]] = []


# Whitelist of claim types allowed to be asserted by Tier1
CLAIM_WHITELIST = {'what', 'why', 'actions', 'severity', 'confidence'}


def _build_bullets(req: Tier1EnhancedRequest) -> List[Dict[str, Any]]:
    top = sorted(req.top_factors, key=lambda f: float(f.get('contribution', 0)), reverse=True)[:3]
    what = f"Observed {len(req.related_events)} related events; top factor: {top[0].get('type') or top[0].get('name')}"
    why = ' & '.join([f"{f.get('type') or f.get('name')} ({f.get('contribution','low')})" for f in top])
    recs = [
        'Isolate the host for triage',
        'Collect memory image and upload to sandbox',
        'Search for IOCs across recent telemetry',
    ]
    return [
        {'type': 'what', 'text': what, 'evidence': [e.get('id') or e.get('event_id') for e in req.related_events[:3]]},
        {'type': 'why', 'text': why, 'evidence': [f.get('id') or f.get('name') for f in top]},
        {'type': 'actions', 'text': '; '.join(recs), 'evidence': []},
    ]


@router.post('/summarize')
def summarize(req: Tier1EnhancedRequest, request: Request):
    if not req.top_factors:
        raise HTTPException(status_code=400, detail='missing_factors')
    bullets = _build_bullets(req)
    # Conservative structured output: apply whitelist and compute simple confidence
    out = []
    claim_ids = []
    # confidence heuristic: normalized average contribution of top factors
    try:
        conf = float(sum(float(f.get('contribution', 0)) for f in req.top_factors[:3]) / max(1, min(3, len(req.top_factors))))
    except Exception:
        conf = 0.5
    for b in bullets:
        btype = b.get('type')
        if btype not in CLAIM_WHITELIST:
            continue
        # minimal evidence snippet: first related event summary (if ref present)
        snippets = []
        for ref in b.get('evidence', [])[:3]:
            try:
                # attempt to find event by id in provided related_events
                ev = next((e for e in req.related_events if (e.get('id') == ref or e.get('event_id') == ref)), None)
                if ev:
                    snippets.append({'event_id': ref, 'summary': ev.get('summary')})
            except Exception:
                pass
        # Record claim with confidence
        cid = record_claim(req.decision_id, b.get('text') or '', btype, [{'ref': r} for r in b.get('evidence', [])], confidence=conf)
        claim_ids.append(cid)
        out.append({'type': btype, 'text': b.get('text'), 'evidence': b.get('evidence', []), 'snippets': snippets, 'confidence': conf})

    sev = f"Severity: {'high' if conf>0.7 else ('medium' if conf>0.4 else 'low')}"
    return {
        'decision_id': req.decision_id,
        'summary': out,
        'severity_line': sev,
        'claim_ids': claim_ids,
        'model': 'local-tier1-template-v2'
    }


@router.get('/claims/pending')
def claims_pending(limit: int = 100):
    return {'pending': list_unadjudicated(limit)}


@router.post('/claims/{claim_id}/adjudicate')
def adjudicate_claim(claim_id: int, payload: dict = Body(...)):
    ok = bool(payload.get('is_correct'))
    try:
        mark_adjudication(claim_id, ok)
        try:
            from src.core.metrics import make_counter
            _c = make_counter('claims_adjudicated_total', 'Total adjudicated claims')
            _c.inc()
        except Exception:
            pass
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'adjudication_failed:{exc}')
    return {'claim_id': claim_id, 'is_correct': ok}


@router.get('/claims/stats')
def claim_statistics():
    return claims_stats()
