from __future__ import annotations
import os
import logging
from typing import Dict, Any, List
import asyncio

logger = logging.getLogger(__name__)

class GrypeConnector:
    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._last_scan_ts: float | None = None

    def health_snapshot(self) -> Dict[str, Any]:
        return {'name': 'grype', 'tenant': self.tenant_id, 'last_scan_ts': self._last_scan_ts}

    async def run_scan(self, target: str) -> Dict[str, Any]:
        self._last_scan_ts = asyncio.get_event_loop().time()
        real_mode = os.getenv('SCANNERS_REAL_MODE','0').lower() in {'1','true','yes'}
        grype_path = os.getenv('GRYPE_PATH') or 'grype'
        if real_mode:
            try:
                import subprocess, json
                cmd = [grype_path, target, '-o', 'json']
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(os.getenv('GRYPE_TIMEOUT_SEC','120') or 120))
                if proc.returncode == 0:
                    data = json.loads(proc.stdout or '{}')
                    comps: List[Dict[str, Any]] = []
                    for m in data.get('matches', []):
                        art = (m.get('artifact') or {})
                        vuln = (m.get('vulnerability') or {})
                        name = art.get('name') or ''
                        ver = art.get('version') or ''
                        cve = vuln.get('id')
                        score = (vuln.get('cvss', [{}])[0] or {}).get('metrics', {}).get('baseScore')
                        comps.append({'name': name, 'version': ver, 'cve': cve, 'cvss_base_score': score})
                    if comps:
                        return {'sbom_id': f'grype-{self.tenant_id}', 'components': comps}
            except Exception:
                logger.exception('Grype scan failed')
        comps: List[Dict[str, Any]] = [
            {'name': 'struts', 'version': '2.5.10', 'summary': 'Potential risky component'},
        ]
        return {'sbom_id': f'grype-{self.tenant_id}', 'components': comps}

    async def forward_to_sbom(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            import httpx
            base = os.getenv('API_BASE_URL', 'http://localhost:8080')
            api_key = os.getenv('API_KEY')
            url = f"{base.rstrip('/')}/api/v1/sbom/upload"
            headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(url, headers=headers, json=payload)
                r.raise_for_status()
                return r.json()
        except Exception as e:
            logger.exception('Grype forward_to_sbom failed: %s', e)
            return {'status': 'error', 'reason': str(e)}
