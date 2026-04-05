from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


class TenableClient:
    """Production Tenable.io API client with VPR cache and fallback to stub mode.

    Features:
    - Real API integration with Tenable.io for VPR enrichment
    - Disk-persisted VPR cache for offline/demo mode
    - Automatic fallback to stub mode when API unavailable
    - Demo mode support via manual VPR seeding (preserves test compatibility)
    - Rate limiting (default 200 req/min)

    Modes:
    - Stub: No API credentials, uses cached/seeded VPR data (for tests/demos)
    - API: Real credentials provided, fetches from Tenable.io
    """

    def __init__(self) -> None:
        self.enabled = False
        self.api_url: str | None = os.getenv('TENABLE_API_URL', 'https://cloud.tenable.com')
        self.access_key: str | None = os.getenv('TENABLE_ACCESS_KEY')
        self.secret_key: str | None = os.getenv('TENABLE_SECRET_KEY')
        self.last_sync: float | None = None
        self.error: str | None = None
        self._vpr_map: dict[str, float] = {}
        self._persist_path = Path(os.getenv('TENABLE_VPR_CACHE', 'data/tenable_vpr.json'))
        self._rate_limit_delay = 60.0 / float(os.getenv('TENABLE_RATE_LIMIT', '200'))
        self._last_request_time = 0.0
        self._http_client: Any = None  # httpx.AsyncClient when available
        self._use_api = False

        try:
            self._load()
        except Exception as e:
            logger.debug(f"Failed to load Tenable VPR cache: {e}")

        # Determine if we can use real API (requires httpx + credentials)
        if HAS_HTTPX and self.access_key and self.secret_key:
            self._use_api = True
            self.enabled = True
            logger.info(f"Tenable client enabled in API mode with {len(self._vpr_map)} cached VPR entries")
        elif self.api_url or self.access_key or self.secret_key:
            # Partial config enables stub mode
            self.enabled = True
            logger.info(f"Tenable client enabled in stub mode with {len(self._vpr_map)} cached VPR entries")

    def _load(self) -> None:
        p = self._persist_path
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
                mp = data.get('vpr_map') or {}
                if isinstance(mp, dict):
                    self._vpr_map = {str(k).upper(): float(v) for k, v in mp.items() if v is not None}
            except Exception:
                pass

    def _save(self) -> None:
        try:
            p = self._persist_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({'vpr_map': self._vpr_map}, indent=2), encoding='utf-8')
        except Exception:
            pass

    async def config(self, body: Dict[str, Any]) -> Dict[str, Any]:
        # In demo, accept api_url, access_key, secret_key, enabled, and optional "vpr" seed map.
        try:
            self.api_url = body.get('api_url') or self.api_url
            self.access_key = body.get('access_key') or self.access_key
            self.secret_key = body.get('secret_key') or self.secret_key
            if 'enabled' in body:
                self.enabled = bool(body.get('enabled'))
            # Allow seeding a VPR map directly for offline demos/tests
            seed = body.get('vpr') or body.get('vpr_map')
            if isinstance(seed, dict):
                for k, v in seed.items():
                    try:
                        self._vpr_map[str(k).upper()] = float(v)
                    except Exception:
                        continue
                self._save()
            return {'configured': True, 'enabled': self.enabled}
        except Exception as e:
            self.error = str(e)
            return {'configured': False, 'enabled': self.enabled, 'error': self.error}

    def status(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'api_url': self.api_url,
            'last_sync': self.last_sync,
            'error': self.error,
            'vpr_cached': len(self._vpr_map),
        }

    def _get_http_client(self):
        """Get or create HTTP client with Tenable auth headers."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not available for API mode")
        if self._http_client is None:
            headers = {
                'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}',
                'Accept': 'application/json',
            }
            import httpx
            self._http_client = httpx.AsyncClient(
                base_url=self.api_url,
                headers=headers,
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
            )
        return self._http_client

    async def _rate_limit(self) -> None:
        """Apply rate limiting between API requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    async def _fetch_vulnerabilities_from_api(self, page_size: int = 1000) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from Tenable.io API with pagination."""
        if not self._use_api:
            return []

        client = self._get_http_client()
        vulns: List[Dict[str, Any]] = []
        offset = 0

        try:
            while True:
                await self._rate_limit()

                # Fetch vulnerabilities with VPR score
                # API docs: https://developer.tenable.com/reference/workbenches-vulnerabilities
                response = await client.get(
                    '/workbenches/vulnerabilities',
                    params={
                        'filter.0.filter': 'plugin.attributes.vpr.score',
                        'filter.0.quality': 'gt',
                        'filter.0.value': '0',
                        'filter.search_type': 'and',
                        'num': page_size,
                        'offset': offset,
                    }
                )

                if response.status_code != 200:
                    logger.error(f"Tenable API error {response.status_code}: {response.text[:200]}")
                    break

                data = response.json()
                batch = data.get('vulnerabilities', [])

                if not batch:
                    break

                vulns.extend(batch)
                logger.info(f"Fetched {len(batch)} vulnerabilities from Tenable (offset={offset})")

                # Check if more pages available
                total = data.get('total_vulnerability_count', 0)
                if offset + len(batch) >= total:
                    break

                offset += page_size

                # Safety limit
                if len(vulns) >= 50000:
                    logger.warning("Reached safety limit of 50k vulnerabilities")
                    break

        except Exception as e:
            logger.error(f"Error fetching Tenable vulnerabilities: {e}")
            self.error = str(e)

        return vulns

    async def sync(self) -> Dict[str, Any]:
        """Sync VPR data from Tenable.io API and update local cache.

        Falls back to stub mode if API unavailable or credentials not configured.
        """
        try:
            # Stub mode: no network access
            if not self._use_api:
                self.last_sync = time.time()
                self.error = None
                logger.debug("Tenable sync in stub mode (no API call)")
                return {'synced': True, 'count': len(self._vpr_map), 'mode': 'stub'}

            # API mode: fetch from Tenable.io
            logger.info("Starting Tenable VPR sync from API")
            vulns = await self._fetch_vulnerabilities_from_api()

            if not vulns:
                logger.warning("No vulnerabilities fetched from Tenable")
                self.last_sync = time.time()
                return {'synced': True, 'count': len(self._vpr_map), 'mode': 'cache', 'fetched': 0}

            # Extract VPR scores and update cache
            updated = 0
            for vuln in vulns:
                try:
                    # Extract CVE list
                    cve_list = vuln.get('cve', [])

                    # Get VPR score from multiple possible locations
                    vpr_score = None
                    vpr_data = vuln.get('vpr', {})
                    if vpr_data:
                        vpr_score = vpr_data.get('score')

                    if not vpr_score:
                        plugin_attrs = vuln.get('plugin', {}).get('attributes', {})
                        vpr_attrs = plugin_attrs.get('vpr', {})
                        vpr_score = vpr_attrs.get('score')

                    # Update cache for each CVE
                    if vpr_score and cve_list:
                        for cve in cve_list:
                            cve_key = str(cve).upper()
                            self._vpr_map[cve_key] = float(vpr_score)
                            updated += 1

                except Exception as e:
                    logger.debug(f"Error processing vulnerability: {e}")
                    continue

            # Persist to disk
            self._save()
            self.last_sync = time.time()
            self.error = None

            logger.info(f"Tenable sync complete: {updated} CVE-VPR mappings, {len(self._vpr_map)} total cached")
            return {
                'synced': True,
                'count': len(self._vpr_map),
                'mode': 'api',
                'fetched': len(vulns),
                'updated': updated,
            }

        except Exception as e:
            logger.error(f"Tenable sync failed: {e}")
            self.error = str(e)
            return {'synced': False, 'error': self.error}

    async def get_vpr_for_cves(self, cves: List[str]) -> Dict[str, float]:
        """Return VPR scores for requested CVEs from local cache.

        Uses cached VPR data populated via sync(). For on-demand API lookups,
        call sync() first or use automatic scheduling.
        """
        out: dict[str, float] = {}
        for c in cves or []:
            try:
                cv = str(c).upper()
                if cv in self._vpr_map:
                    out[cv] = float(self._vpr_map[cv])
            except Exception:
                continue
        return out

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
            logger.debug("Tenable HTTP client closed")


CLIENT = TenableClient()

__all__ = ['CLIENT', 'TenableClient']
