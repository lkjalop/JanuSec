from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter(prefix='/api/v1/feedback', tags=['Feedback'])


class FeedbackPayload(BaseModel):
    rule_id: str
    is_true_positive: bool


@router.post('/rule_vote')
def rule_vote(payload: FeedbackPayload) -> Dict[str, Any]:
    return {'status': 'ok'}


@router.get('/ping')
def ping() -> Dict[str, Any]:
    return {'ok': True}


__all__ = ['router']
