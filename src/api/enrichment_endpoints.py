from __future__ import annotations

import os, asyncio, csv, json, http.client
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from src.enrichment.kev_epss import ingest_kev_csv, ingest_epss_csv, kev_lookup, epss_lookup  # type: ignore

router = APIRouter(prefix="/api/v1/enrichment", tags=["enrichment"])

_KEV_SOURCE = os.getenv('KEV_SOURCE_URL', 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv')
_EPSS_SOURCE = os.getenv('EPSS_SOURCE_URL', 'https://epss.cyentia.com/epss_scores.csv')

def _download_to_temp(url: str, kind: str) -> Optional[str]:
    try:
        if not url.startswith('http'):  # only http(s)
            return None
        # Simplistic built-in HTTP client usage (avoid requests dependency at import)
        scheme = 'https' if url.startswith('https://') else 'http'
        host_path = url.split('://', 1)[1]
        host, path = host_path.split('/', 1)
        conn = http.client.HTTPSConnection(host, timeout=15) if scheme == 'https' else http.client.HTTPConnection(host, timeout=15)
        conn.request('GET', '/' + path)
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = resp.read()
        tmp = f"data/{kind}_latest.csv"
        os.makedirs('data', exist_ok=True)
        with open(tmp, 'wb') as fh:
            fh.write(data)
        return tmp
    except Exception:
        return None

@router.post('/kev/refresh', operation_id='enrichment_kev_refresh')
def kev_refresh() -> Dict[str, Any]:
    path = _download_to_temp(_KEV_SOURCE, 'kev')
    if not path:
        raise HTTPException(status_code=502, detail='kev_download_failed')
    count = ingest_kev_csv(path)
    return {'status':'ok','entries':count}

@router.post('/epss/refresh')
def epss_refresh() -> Dict[str, Any]:
    path = _download_to_temp(_EPSS_SOURCE, 'epss')
    if not path:
        raise HTTPException(status_code=502, detail='epss_download_failed')
    count = ingest_epss_csv(path)
    return {'status':'ok','entries':count}

@router.get('/kev/{cve}')
def kev_get(cve: str) -> Dict[str, Any]:
    rec = kev_lookup(cve.upper())
    if not rec:
        raise HTTPException(status_code=404, detail='not_found')
    return {'cve': cve.upper(), 'kev': True, 'record': rec}

@router.get('/epss/{cve}')
def epss_get(cve: str) -> Dict[str, Any]:
    rec = epss_lookup(cve.upper())
    if not rec:
        raise HTTPException(status_code=404, detail='not_found')
    # EPSS datasets typically include probability column (e.g., EPSS)
    prob = None
    for k in ('epss','EPSS','probability','score'):
        if k in rec:
            try:
                prob = float(rec[k])
            except Exception:
                prob = rec[k]
            break
    return {'cve': cve.upper(), 'epss': prob, 'record': rec}

__all__ = ['router']
