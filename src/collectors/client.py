from __future__ import annotations
from typing import Dict, Any
from datetime import datetime
import json
import requests


def build_telemetry_payload(collector_id: str, status: str, error: str | None = None, extras: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = {
        'collector_id': collector_id,
        'status': status,
        'error': error,
        'ts': datetime.utcnow().isoformat() + 'Z',
    }
    if extras:
        payload.update({'extras': extras})
    return payload


def send_telemetry(base_url: str, collector_id: str, payload: Dict[str, Any], api_key: str | None = None) -> requests.Response:
    url = base_url.rstrip('/') + '/api/v1/collector_telemetry'
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['x-api-key'] = api_key
    return requests.post(url, json=payload, headers=headers, timeout=10)
