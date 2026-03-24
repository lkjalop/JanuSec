from __future__ import annotations
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict
from src.core.calibration.weights_calibrator import apply_vote
from src.config import risk_loader

router = APIRouter(prefix='/api/v1/feedback', tags=['Feedback'])

class CalibrationBatchPayload(BaseModel):  # type: ignore[misc]
    votes: Dict[str, int]  # factor -> vote (-1|1)

@router.post('/calibration/batch', summary='Apply batch calibration votes to factor weights')  # type: ignore[misc]
async def calibration_batch(payload: CalibrationBatchPayload, x_api_key: str | None = Header(None)) -> dict:
    if not x_api_key:
        raise HTTPException(status_code=403, detail='forbidden')
    updated: Dict[str, float] = {}
    for factor, vote in (payload.votes or {}).items():
        if vote not in (-1, 1):
            raise HTTPException(status_code=400, detail=f'invalid_vote:{factor}')
        try:
            weights = apply_vote(factor, vote)
            updated[factor] = float(weights.get(factor, 0.0))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'calibration_failed:{factor}:{e}')
    return {'status': 'ok', 'updated': updated, 'hash': risk_loader.config_hash()}

__all__ = ['router']
