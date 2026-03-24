from __future__ import annotations
import os
import logging
from typing import Dict, Any, List, Tuple
import asyncio
import random

logger = logging.getLogger(__name__)

class SnykConnector:
    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._last_scan_ts: float | None = None

    def health_snapshot(self) -> Dict[str, Any]:
        return {'name': 'snyk', 'tenant': self.tenant_id, 'last_scan_ts': self._last_scan_ts}

    async def run_scan(self, project: str) -> Dict[str, Any]:
        self._last_scan_ts = asyncio.get_event_loop().time()
        real_mode = os.getenv('SCANNERS_REAL_MODE','0').lower() in {'1','true','yes'}
        api_token = os.getenv('SNYK_TOKEN')
        api_base = os.getenv('SNYK_API_BASE', 'https://api.snyk.io')
        org_id = os.getenv('SNYK_ORG_ID')
        project_id = os.getenv('SNYK_PROJECT_ID') or project
        if real_mode and api_token and org_id and project_id:
            try:
                import httpx
                headers = {'Authorization': f'token {api_token}'}
                timeout = int(os.getenv('SNYK_TIMEOUT_SEC','60') or 60)
                max_pages = int(os.getenv('SNYK_MAX_PAGES','10') or 10)
                page_size = int(os.getenv('SNYK_PAGE_SIZE','100') or 100)

                async def _fetch_with_retry(client: httpx.AsyncClient, url: str, headers: dict) -> Tuple[httpx.Response, int]:
                    attempts = 0
                    backoff = 0.5
                    while True:
                        try:
                            resp = await client.get(url, headers=headers)
                            if resp.status_code == 429:
                                attempts += 1
                                if attempts > 5:
                                    return resp, attempts
                                # exponential backoff with jitter
                                jitter = backoff * (0.7 + random.random() * 0.6)
                                await asyncio.sleep(jitter)
                                backoff = min(8.0, backoff * 2)
                                continue
                            resp.raise_for_status()
                            return resp, attempts
                        except (httpx.HTTPStatusError, httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError) as e:
                            attempts += 1
                            if attempts > 3:
                                # return the last response-like object when available
                                return getattr(e, 'response', None), attempts
                            jitter = backoff * (0.7 + random.random() * 0.6)
                            await asyncio.sleep(jitter)
                            backoff = min(8.0, backoff * 2)

                def _next_link(data: Dict[str, Any], resp: httpx.Response) -> str | None:
                    # Try various locations for next page across API variants
                    nxt = data.get('next') or None
                    if not nxt:
                        links = data.get('links') or {}
                        nxt = links.get('next') or None
                    if not nxt:
                        meta = data.get('meta') or {}
                        nxt = meta.get('next') or None
                    if not nxt:
                        # Parse Link header: <url>; rel="next"
                        link = resp.headers.get('link') or resp.headers.get('Link')
                        if link and 'rel="next"' in link:
                            try:
                                start = link.find('<')
                                end = link.find('>')
                                if start >= 0 and end > start:
                                    nxt = link[start+1:end]
                            except Exception:
                                nxt = None
                    return nxt

                async with httpx.AsyncClient(timeout=timeout) as client:
                    comps: List[Dict[str, Any]] = []
                    # Prefer v1 issues route, fall back to rest API
                    url = f"{api_base.rstrip('/')}/v1/org/{org_id}/project/{project_id}/issues?perPage={page_size}"
                    seen_pages = 0
                    errors: List[Dict[str, Any]] = []
                    while url and seen_pages < max_pages:
                        resp, retries = await _fetch_with_retry(client, url, headers)
                        if resp is None or resp.status_code >= 400:
                            try:
                                code = (resp.status_code if resp is not None else None)
                            except Exception:
                                code = None
                            errors.append({'page': seen_pages+1, 'status_code': code, 'retries': retries, 'url': url})
                            break
                        data = resp.json()
                        issues = data.get('issues')
                        if not isinstance(issues, list):
                            # Snyk REST may use `data` payload with `attributes`
                            issues = data.get('data') or []
                        for it in issues:
                            # Normalize across variants
                            pkg = it.get('pkgName') or it.get('package') or (it.get('attributes') or {}).get('packageName') or ''
                            ver = it.get('pkgVersion') or it.get('version') or (it.get('attributes') or {}).get('packageVersion') or ''
                            identifiers = it.get('identifiers') or (it.get('attributes') or {}).get('identifiers') or {}
                            cve_list = identifiers.get('CVE') or identifiers.get('cve') or []
                            cve = (cve_list[0] if isinstance(cve_list, list) and cve_list else None)
                            score = it.get('cvssScore') or it.get('cvss') or (it.get('attributes') or {}).get('cvssScore')
                            comps.append({'name': pkg, 'version': ver, 'cve': cve, 'cvss_base_score': score})
                        next_url = _next_link(data, resp)
                        url = next_url
                        seen_pages += 1
                    if comps:
                        return {'sbom_id': f'snyk-{self.tenant_id}', 'components': comps, 'meta': {'pages': seen_pages, 'page_size': page_size}}
                    # real-mode returned no components; attach error meta
                    return {'sbom_id': f'snyk-{self.tenant_id}', 'components': [], 'errors': errors, 'meta': {'pages': seen_pages, 'page_size': page_size}}
            except Exception as e:
                logger.exception('Snyk scan failed: %s', e)
        comps: List[Dict[str, Any]] = [
            {'name': 'log4j-core', 'version': '2.14.1', 'cve': 'CVE-2021-44228', 'cvss_base_score': 10.0, 'summary': 'Log4Shell'},
            {'name': 'commons-io', 'version': '2.6'},
        ]
        return {'sbom_id': f'snyk-{self.tenant_id}', 'components': comps}

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
            logger.exception('Snyk forward_to_sbom failed: %s', e)
            return {'status': 'error', 'reason': str(e)}
