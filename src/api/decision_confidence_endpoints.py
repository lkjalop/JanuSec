from fastapi import APIRouter, HTTPException
import time

router = APIRouter(prefix="/api/v1/decisions", tags=["decisions-confidence"])

DOMAIN_STAGE_ORDER = [
    'email:', 'identity:', 'remote:', 'endpoint:', 'net:', 'cloud:', 'data:', 'app:', 'api:', 'corr_'
]

DOMAIN_BASE_INCREMENTS = {
    'email:': 0.10,
    'identity:': 0.08,
    'remote:': 0.10,
    'endpoint:': 0.12,
    'net:': 0.10,
    'cloud:': 0.09,
    'data:': 0.14,
    'app:': 0.07,
    'api:': 0.07,
    'corr_': 0.08,  # correlation bonus
}

def _domain_prefix(f: str) -> str:
    for p in DOMAIN_STAGE_ORDER:
        if f.startswith(p):
            return p
    return 'other'

@router.get("/{event_id}/confidence_story")
async def confidence_story(event_id: str):
    try:
        from src.api import runtime_state
        dec = runtime_state.cache_get(event_id)
    except Exception:
        dec = None
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    factors = dec.get('factors', [])
    story = []
    running = 0.0
    used_domains = set()
    for f in factors:
        dom = _domain_prefix(f)
        if dom == 'other':
            continue
        base = DOMAIN_BASE_INCREMENTS.get(dom, 0.05)
        # Diminishing returns if same domain repeats
        if dom in used_domains:
            incr = base * 0.4
        else:
            incr = base
            used_domains.add(dom)
        running = min(1.0, running + incr)
        story.append({
            'factor': f,
            'domain': dom.rstrip(':'),
            'increment': round(incr, 3),
            'running_confidence': round(running, 3)
        })
    # Align final narrative confidence with stored decision when present
    final_conf = float(dec.get('confidence') or 0.0)
    if story and abs(final_conf - story[-1]['running_confidence']) > 0.05:
        story.append({
            'factor': 'calibration_adjust',
            'domain': 'calibration',
            'increment': round(max(0.0, final_conf - story[-1]['running_confidence']), 3),
            'running_confidence': round(final_conf, 3)
        })
    return {
        'event_id': event_id,
        'final_confidence': final_conf,
        'narrative': story,
        'domains_contributing': sorted([s['domain'] for s in story if s['domain'] not in {'calibration'}]),
        'generated_ts': time.time()
    }

__all__ = ['router']
