from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


class WhoisRequest(BaseModel):
    query: str


@router.post('/playbook/whois')
def whois_lookup(req: WhoisRequest) -> Dict[str, Any]:
    # Stub: replace with a call to a whois service or `python-whois`.
    if not req.query:
        raise HTTPException(status_code=400, detail='missing query')
    logger.info('whois lookup stub for %s', req.query)
    return {'query': req.query, 'registrar': 'example-registrar', 'creation_date': '2020-01-01'}


class PivotRequest(BaseModel):
    src: str
    pivot_type: Optional[str] = 'logs'


@router.post('/playbook/pivot')
def pivot_to_logs(req: PivotRequest) -> Dict[str, Any]:
    # Stub: perform pivot into logging/ELK indices and return a search token
    logger.info('pivot stub for %s to %s', req.src, req.pivot_type)
    return {'token': 'pivot-token-123', 'count': 0}


class EvidenceAttachRequest(BaseModel):
    event_id: str
    evidence_type: str
    data_ref: str


@router.post('/playbook/evidence')
def attach_evidence(req: EvidenceAttachRequest) -> Dict[str, Any]:
    # Stub: record evidence linkage in DB or object store
    logger.info('attach evidence stub: %s %s', req.event_id, req.evidence_type)
    return {'status': 'ok', 'event_id': req.event_id}
