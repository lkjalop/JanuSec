from __future__ import annotations

import os
import time
import uuid
from collections import Counter
from typing import Dict

from fastapi import APIRouter, Depends

from ..alerts_endpoints import append_alert
from ..dependencies import get_platform_state, get_tenant_context
from ..schemas import DecisionRecord, DecisionResponse, IngestEvent, TenantContext
from ..state import PlatformState

router = APIRouter()

_LINEAGE_COUNTS: Counter[tuple[str, str]] = Counter()
_BENIGN_LINEAGE = {('explorer.exe', 'notepad.exe')}
_LINEAGE_CACHE_ENABLED = os.getenv('ENDPOINT_LINEAGE_CACHE_ENABLED', '1').lower() not in {'0', 'false', 'no'}


def _guardrail_single_pass(_: IngestEvent) -> None:
    """Placeholder for additional validation hooks."""


def _endpoint_lineage_factors(process_name: str | None, parent_name: str | None) -> list[str]:
    if not _LINEAGE_CACHE_ENABLED:
        return []
    if not process_name or not parent_name:
        return []
    proc = process_name.lower()
    parent = parent_name.lower()
    key = (parent, proc)
    if key in _BENIGN_LINEAGE:
        return []
    threshold = int(os.getenv('ENDPOINT_LINEAGE_RARE_THRESHOLD', '5'))
    count = _LINEAGE_COUNTS[key]
    _LINEAGE_COUNTS[key] = count + 1
    if count < threshold:
        return [f'endpoint:rare_lineage:{parent}->{proc}']
    return []


def _decide(event: IngestEvent) -> DecisionRecord:
    verdict = 'allow'
    confidence = 0.5
    factors: list[str] = []

    process_name = (event.details.get('process') or {}).get('name') if event.details else None
    parent_name = (event.details.get('process') or {}).get('parent_name') if event.details else None
    domain = event.domain or (event.details.get('domain') if event.details else None)

    factors.extend(_endpoint_lineage_factors(process_name, parent_name))

    risk_processes = {'powershell.exe', 'cmd.exe', 'wscript.exe', 'rundll32.exe'}
    if process_name and process_name.lower() in risk_processes:
        factors.append(f'process_high_risk:{process_name.lower()}')

    if process_name and process_name.lower().startswith('mimikatz'):
        verdict = 'quarantine'
        confidence = 0.95
        factors.append('proc_signature:mimikatz')
    elif domain and any(domain.endswith(s) for s in ('.xyz', '.bad')):
        verdict = 'deny'
        confidence = 0.80
        factors.append('domain_risky_suffix')
    else:
        factors.append('baseline_allow')

    if any(f.startswith('endpoint:') for f in factors) or any(f.startswith('process_high_risk:') for f in factors) or verdict not in {'allow', 'baseline_allow'}:
        if verdict == 'allow' or verdict == 'baseline_allow':
            verdict = 'alert'
        confidence = max(confidence, 0.8 if verdict == 'alert' else confidence)

    return DecisionRecord(
        event_id=event.id or uuid.uuid4().hex,
        verdict=verdict,
        confidence=confidence,
        factors=factors,
        timestamp=time.time(),
    )


@router.post('/api/v1/events', response_model=DecisionResponse)
def ingest_event(
    payload: IngestEvent,
    ctx: TenantContext = Depends(get_tenant_context),
    state: PlatformState = Depends(get_platform_state),
) -> DecisionResponse:
    _guardrail_single_pass(payload)
    decision = _decide(payload)
    decision.tenant_id = ctx.tenant_id
    state.record_decision(decision, heavy=bool(payload.parent_process))

    if decision.verdict.lower() != 'allow':
        tenant_id = decision.tenant_id or ctx.tenant_id
        alert_payload = {
            'id': decision.event_id,
            'verdict': decision.verdict,
            'confidence': decision.confidence,
            'score': decision.confidence,
            'factors': decision.factors,
            'ts': decision.timestamp,
            'tenant_id': tenant_id,
        }
        append_alert(alert_payload)

    return DecisionResponse(
        event_id=decision.event_id,
        verdict=decision.verdict,
        confidence=decision.confidence,
        factors=decision.factors,
        tenant_id=decision.tenant_id or ctx.tenant_id,
    )
