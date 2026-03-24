from __future__ import annotations
import os
import logging
from typing import Dict, Any, List
import asyncio

logger = logging.getLogger(__name__)

class SyftConnector:
    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._last_scan_ts: float | None = None

    def health_snapshot(self) -> Dict[str, Any]:
        return {'name': 'syft', 'tenant': self.tenant_id, 'last_scan_ts': self._last_scan_ts}

    async def run_scan(self, target: str) -> Dict[str, Any]:
        self._last_scan_ts = asyncio.get_event_loop().time()
        real_mode = os.getenv('SCANNERS_REAL_MODE','0').lower() in {'1','true','yes'}
        syft_path = os.getenv('SYFT_PATH') or 'syft'
        if real_mode:
            try:
                import subprocess, json
                cmd = [syft_path, target, '-o', 'json']
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(os.getenv('SYFT_TIMEOUT_SEC','120') or 120))
                if proc.returncode == 0:
                    data = json.loads(proc.stdout or '{}')
                    comps: List[Dict[str, Any]] = []
                    deps: List[Dict[str, Any]] = []
                    arts = data.get('artifacts') or []
                    rels = data.get('artifactRelationships') or data.get('relationships') or []
                    name_map = {}
                    for a in arts:
                        name = a.get('name') or a.get('id') or ''
                        ver = a.get('version') or ''
                        comps.append({'name': name, 'version': ver})
                        name_map[a.get('id') or name] = name
                    # Build simple dependencies list from relationships
                    dep_graph = {}
                    for r in rels:
                        try:
                            src = r.get('from') or r.get('source')
                            dst = r.get('to') or r.get('target')
                            typ = (r.get('type') or r.get('relationship'))
                            if str(typ).lower().find('depends') >= 0:
                                s = name_map.get(src) or src
                                d = name_map.get(dst) or dst
                                dep_graph.setdefault(s, set()).add(d)
                        except Exception:
                            continue
                    for s, children in dep_graph.items():
                        # Use CycloneDX-compatible key 'dependsOn' so downstream
                        # dependency graph builders and SBOM endpoints recognize it.
                        deps.append({'ref': s, 'dependsOn': sorted(list(children))})
                    return {'sbom_id': f'syft-{self.tenant_id}', 'components': comps, 'relationships': deps}
            except Exception:
                logger.exception('Syft scan failed')
        comps: List[Dict[str, Any]] = [
            {'name': 'commons-io', 'version': '2.6'},
        ]
        return {'sbom_id': f'syft-{self.tenant_id}', 'components': comps}

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
            logger.exception('Syft forward_to_sbom failed: %s', e)
            return {'status': 'error', 'reason': str(e)}
