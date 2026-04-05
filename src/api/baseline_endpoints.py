from __future__ import annotations

from fastapi import APIRouter, HTTPException

try:
    from baseline.services import get_nxdomain_baseline, get_asn_rarity, record_dns_event, record_asn  # type: ignore
except Exception:
    from src.baseline.services import get_nxdomain_baseline, get_asn_rarity, record_dns_event, record_asn  # type: ignore

router = APIRouter(prefix='/api/v1/baseline', tags=['Baselines'])

@router.get('/nxdomain')
async def baseline_nxdomain(window_seconds: int = 3600) -> dict:
    return get_nxdomain_baseline(window_seconds)

@router.get('/asn')
async def baseline_asn() -> dict:
    return get_asn_rarity()

@router.post('/event/dns')
async def ingest_dns_event(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')
    success = bool(payload.get('success', True))
    record_dns_event(success)
    return {'ok': True}

@router.post('/event/asn')
async def ingest_asn_event(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')
    asn = str(payload.get('asn') or '').strip()
    if not asn:
        raise HTTPException(status_code=400, detail='missing_asn')
    record_asn(asn)
    return {'ok': True}
