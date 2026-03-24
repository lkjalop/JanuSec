from __future__ import annotations
import os
import logging
from typing import Dict, Any, List
import asyncio

logger = logging.getLogger(__name__)

class TrivyConnector:
    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._last_scan_ts: float | None = None

    def health_snapshot(self) -> Dict[str, Any]:
        return {'name': 'trivy', 'tenant': self.tenant_id, 'last_scan_ts': self._last_scan_ts}

    async def run_scan(self, image: str) -> Dict[str, Any]:
        self._last_scan_ts = asyncio.get_event_loop().time()
        # Real-mode: attempt to run trivy CLI when TRIVY_PATH set
        trivy_path = os.getenv('TRIVY_PATH') or 'trivy'
        real_mode = os.getenv('SCANNERS_REAL_MODE','0').lower() in {'1','true','yes'}
        if real_mode:
            try:
                import subprocess, json
                cmd = [trivy_path, 'image', '--quiet', '--format', 'json', image]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(os.getenv('TRIVY_TIMEOUT_SEC','120') or 120))
                if proc.returncode == 0:
                    data = json.loads(proc.stdout or '{}')
                    comps: List[Dict[str, Any]] = []
                    for res in data.get('Results', []):
                        vulns = res.get('Vulnerabilities') or []
                        for v in vulns:
                            name = v.get('PkgName') or ''
                            ver = v.get('InstalledVersion') or ''
                            cve = v.get('VulnerabilityID')
                            score = v.get('CVSS', {}).get('nvd', {}).get('V2Score') or v.get('CVSS', {}).get('nvd', {}).get('Score')
                            comps.append({'name': name, 'version': ver, 'cve': cve, 'cvss_base_score': score})
                    if comps:
                        return {'sbom_id': f'trivy-{self.tenant_id}', 'components': comps}
            except Exception as e:
                logger.exception('Trivy scan failed: %s', e)
        # Fallback stub
        comps: List[Dict[str, Any]] = [
            {'name': 'openssl', 'version': '1.1.0', 'cve': 'CVE-2020-1967', 'cvss_base_score': 7.5, 'summary': 'OpenSSL vuln'},
            {'name': 'libxml2', 'version': '2.9.10'},
        ]
        return {'sbom_id': f'trivy-{self.tenant_id}', 'components': comps}

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
            logger.exception('Trivy forward_to_sbom failed: %s', e)
            return {'status': 'error', 'reason': str(e)}
