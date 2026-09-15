from __future__ import annotations

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional

from src.core.monitoring.ingestion_anomaly import IngestionAnomalyDetector

router = APIRouter(prefix='/api/v1/health', tags=['Health'])

# Shared detector instance
_DETECTOR = IngestionAnomalyDetector()


@router.get('/ingestion')
async def ingestion_health() -> Dict[str, Any]:
    summary = _DETECTOR.get_summary()
    gaps = _DETECTOR.detect_gaps()
    return {'summary': summary, 'active_gaps': gaps}


@router.get('/ingestion/{source}')
async def ingestion_health_source(source: str) -> Dict[str, Any]:
    s = _DETECTOR.last_event_received(source)
    return {'source': source, 'last_seen': s.get('last_seen'), 'seconds_since': s.get('seconds_since')}


@router.post('/ingestion/record/{source}')
async def ingestion_record(source: str) -> Dict[str, Any]:
    # minimal endpoint to simulate event recording for tests/demo
    _DETECTOR.record_event(source)
    return {'status': 'recorded', 'source': source}


__all__ = ['router']
