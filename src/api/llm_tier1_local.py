from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

router = APIRouter(prefix='/api/v1/llm', tags=['llm'])


class Tier1Request(BaseModel):
    event_id: str
    factors: List[Dict[str, Any]]  # each factor: {type, value, contribution}
    top_events: List[Dict[str, Any]] = []  # up to 10 events


def _fact_check(sentences: List[str], factors: List[Dict[str, Any]], top_events: List[Dict[str, Any]]) -> List[str]:
    # Basic fact-check: ensure any mention of a field/value exists in inputs
    ok = []
    inputs = []
    for f in factors:
        inputs.append(str(f.get('value')))
    for e in top_events:
        inputs.append(str(e.get('id') or e.get('event_id') or ''))
    for s in sentences:
        keep = False
        for token in inputs:
            if token and token in s:
                keep = True
                break
        if keep:
            ok.append(s)
    return ok


@router.post('/tier1/local')
def tier1_local(req: Tier1Request):
    if not req.factors:
        raise HTTPException(status_code=400, detail='no_factors')
    # Build 3 bullet summary: what, why, recommended action + 1-line severity
    top3 = sorted(req.factors, key=lambda f: float(f.get('contribution', 0)), reverse=True)[:3]
    what = f"Observed {top3[0].get('type')}={top3[0].get('value')} (evidence: {top3[0].get('source','unknown')})"
    why = ' + '.join([f"{f.get('type')}={f.get('value')}" for f in top3])
    action = 'Recommended: investigate host, collect memory, and enrich IOC.'
    sev = f"Severity: {round(sum(float(f.get('contribution',0)) for f in top3)/3,2)}"
    bullets = [what, why, action]
    # Fact-check sentences against inputs
    ok_sentences = _fact_check(bullets + [sev], req.factors, req.top_events)
    # Return templated response with provenance minimal
    return {
        'summary': bullets,
        'severity_line': sev,
        'fact_checked': ok_sentences,
        'provenance': {'model': 'local-tier1', 'prompt_template': 'tier1_brief_v1'}
    }
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict

router = APIRouter(prefix='/api/v1/llm/tier1', tags=['llm'])


class Tier1Request(BaseModel):
    decision_id: str
    top_factors: List[Dict]
    related_events: List[Dict] = []


@router.post('/summarize')
def summarize(req: Tier1Request):
    # Very conservative templated summary — do not fabricate facts.
    if not req.top_factors:
        raise HTTPException(status_code=400, detail='missing_factors')
    # Build three bullets: what, why, recommended action
    what = f"Observed {len(req.related_events)} related events; top factor: {req.top_factors[0].get('type') or req.top_factors[0].get('name') }"
    why_parts = []
    for f in req.top_factors[:3]:
        why_parts.append(f"{f.get('type') or f.get('name')} ({f.get('contribution', 'low')})")
    why = ' & '.join(why_parts)
    rec = []
    rec.append('Isolate the host for triage')
    rec.append('Collect memory image and upload to sandbox')
    rec.append('Search for IOCs across recent telemetry')
    # fact-check: ensure claims are present in related_events
    provenance = []
    for e in req.related_events[:5]:
        provenance.append({'event_id': e.get('id') or e.get('event_id'), 'summary': e.get('summary') or ''})

    return {
        'decision_id': req.decision_id,
        'summary': {
            'what': what,
            'why': why,
            'recommended_actions': rec,
            'severity_line': f"Severity: {req.top_factors[0].get('severity','medium')}",
        },
        'provenance': provenance,
        'model': 'local-tier1-template',
    }
