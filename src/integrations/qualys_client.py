from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


class QualysClient:
    """Production Qualys VMDR API client with vulnerability cache and fallback to stub mode.

    Features:
    - Real API integration with Qualys VMDR for vulnerability data
    - Disk-persisted vulnerability cache for offline/demo mode
    - Automatic fallback to stub mode when API unavailable
    - Demo mode support (preserves test compatibility)
    - XML parsing for Qualys API responses
    - Rate limiting (default 300 req/hour for Qualys API tier 1)

    Modes:
    - Stub: No API credentials, uses cached data (for tests/demos)
    - API: Real credentials provided, fetches from Qualys VMDR
    """

    def __init__(self) -> None:
        self.enabled = False
        self.api_url: str | None = os.getenv('QUALYS_API_URL', 'https://qualysapi.qualys.com')
        self.username: str | None = os.getenv('QUALYS_USERNAME')
        self.password: str | None = os.getenv('QUALYS_PASSWORD')
        self.last_sync: float | None = None
        self.error: str | None = None
        self._vuln_cache: dict[str, Dict[str, Any]] = {}  # CVE -> vulnerability data
        self._persist_path = Path(os.getenv('QUALYS_VULN_CACHE', 'data/qualys_vulns.json'))
        self._rate_limit_delay = 3600.0 / float(os.getenv('QUALYS_RATE_LIMIT', '300'))  # req/hour
        self._last_request_time = 0.0
        self._http_client: Any = None
        self._use_api = False

        try:
            self._load()
        except Exception as e:
            logger.debug(f"Failed to load Qualys vulnerability cache: {e}")

        # Determine if we can use real API (requires httpx + credentials)
        if HAS_HTTPX and self.username and self.password:
            self._use_api = True
            self.enabled = True
            logger.info(f"Qualys client enabled in API mode with {len(self._vuln_cache)} cached vulnerabilities")
        elif self.api_url or self.username or self.password:
            # Partial config enables stub mode
            self.enabled = True
            logger.info(f"Qualys client enabled in stub mode with {len(self._vuln_cache)} cached vulnerabilities")

    def _load(self) -> None:
        """Load vulnerability cache from disk."""
        p = self._persist_path
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
                cache = data.get('vuln_cache') or {}
                if isinstance(cache, dict):
                    self._vuln_cache = cache
            except Exception as e:
                logger.warning(f"Error loading Qualys cache: {e}")

    def _save(self) -> None:
        """Save vulnerability cache to disk."""
        try:
            p = self._persist_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({'vuln_cache': self._vuln_cache}, indent=2), encoding='utf-8')
        except Exception as e:
            logger.warning(f"Error saving Qualys cache: {e}")

    async def config(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Configure Qualys client with API credentials."""
        try:
            self.api_url = body.get('api_url') or self.api_url
            self.username = body.get('username') or self.username
            self.password = body.get('password') or self.password
            if 'enabled' in body:
                self.enabled = bool(body.get('enabled'))

            # Allow seeding vulnerability data for demos/tests
            seed = body.get('vulns') or body.get('vuln_cache')
            if isinstance(seed, dict):
                for cve, data in seed.items():
                    try:
                        self._vuln_cache[str(cve).upper()] = data
                    except Exception:
                        continue
                self._save()

            return {'configured': True, 'enabled': self.enabled}
        except Exception as e:
            self.error = str(e)
            return {'configured': False, 'enabled': self.enabled, 'error': self.error}

    def status(self) -> Dict[str, Any]:
        """Get current status of Qualys integration."""
        return {
            'enabled': self.enabled,
            'api_url': self.api_url,
            'last_sync': self.last_sync,
            'error': self.error,
            'vulns_cached': len(self._vuln_cache),
        }

    def _get_http_client(self):
        """Get or create HTTP client with Qualys basic auth."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not available for API mode")
        if self._http_client is None:
            import httpx
            self._http_client = httpx.AsyncClient(
                base_url=self.api_url,
                auth=(self.username, self.password),
                timeout=httpx.Timeout(60.0),
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

    def _parse_qualys_xml(self, xml_data: str) -> List[Dict[str, Any]]:
        """Parse Qualys Knowledge Base XML response.

        Extracts vulnerability data including CVE IDs, CVSS scores, and severity.
        """
        vulns: List[Dict[str, Any]] = []

        try:
            root = ET.fromstring(xml_data)

            # Find all VULN elements
            for vuln_elem in root.findall('.//VULN'):
                try:
                    vuln_data: Dict[str, Any] = {}

                    # Extract QID
                    qid_elem = vuln_elem.find('QID')
                    if qid_elem is not None and qid_elem.text:
                        vuln_data['qid'] = qid_elem.text

                    # Extract severity
                    severity_elem = vuln_elem.find('SEVERITY_LEVEL')
                    if severity_elem is not None and severity_elem.text:
                        vuln_data['severity'] = int(severity_elem.text)

                    # Extract title
                    title_elem = vuln_elem.find('TITLE')
                    if title_elem is not None and title_elem.text:
                        vuln_data['title'] = title_elem.text

                    # Extract CVSS base score
                    cvss_base = vuln_elem.find('.//CVSS_BASE')
                    if cvss_base is not None and cvss_base.text:
                        vuln_data['cvss_base'] = float(cvss_base.text)

                    # Extract CVSS v3 score if available
                    cvss_v3 = vuln_elem.find('.//CVSS_V3_BASE')
                    if cvss_v3 is not None and cvss_v3.text:
                        vuln_data['cvss_v3'] = float(cvss_v3.text)

                    # Extract CVE list
                    cve_list_elem = vuln_elem.find('.//CVE_LIST')
                    if cve_list_elem is not None:
                        cves = []
                        for cve_elem in cve_list_elem.findall('CVE'):
                            cve_id = cve_elem.find('ID')
                            if cve_id is not None and cve_id.text:
                                cves.append(cve_id.text)
                        if cves:
                            vuln_data['cves'] = cves

                    # Only add if we have CVEs
                    if 'cves' in vuln_data and vuln_data['cves']:
                        vulns.append(vuln_data)

                except Exception as e:
                    logger.debug(f"Error parsing VULN element: {e}")
                    continue

        except ET.ParseError as e:
            logger.error(f"Error parsing Qualys XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing Qualys XML: {e}")

        return vulns

    async def _fetch_vulnerabilities_from_api(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from Qualys Knowledge Base API."""
        if not self._use_api:
            return []

        client = self._get_http_client()
        vulns: List[Dict[str, Any]] = []

        try:
            await self._rate_limit()

            # Fetch vulnerabilities with CVE information
            # API docs: https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf
            logger.info("Fetching vulnerabilities from Qualys Knowledge Base API")
            response = await client.post(
                '/api/2.0/fo/knowledge_base/vuln/',
                data={
                    'action': 'list',
                    'details': 'All',
                    'show_qid_change_log': '0',
                }
            )

            if response.status_code != 200:
                logger.error(f"Qualys API error {response.status_code}: {response.text[:200]}")
                self.error = f"API returned {response.status_code}"
                return []

            # Parse XML response
            vulns = self._parse_qualys_xml(response.text)
            logger.info(f"Parsed {len(vulns)} vulnerabilities with CVE data from Qualys")

        except Exception as e:
            logger.error(f"Error fetching Qualys vulnerabilities: {e}")
            self.error = str(e)

        return vulns

    async def sync(self) -> Dict[str, Any]:
        """Sync vulnerability data from Qualys VMDR API and update local cache.

        Falls back to stub mode if API unavailable or credentials not configured.
        """
        try:
            # Stub mode: no network access
            if not self._use_api:
                self.last_sync = time.time()
                self.error = None
                logger.debug("Qualys sync in stub mode (no API call)")
                return {'synced': True, 'count': len(self._vuln_cache), 'mode': 'stub'}

            # API mode: fetch from Qualys VMDR
            logger.info("Starting Qualys vulnerability sync from API")
            vulns = await self._fetch_vulnerabilities_from_api()

            if not vulns:
                logger.warning("No vulnerabilities fetched from Qualys")
                self.last_sync = time.time()
                return {'synced': True, 'count': len(self._vuln_cache), 'mode': 'cache', 'fetched': 0}

            # Update cache with vulnerability data indexed by CVE
            updated = 0
            for vuln in vulns:
                try:
                    cves = vuln.get('cves', [])
                    for cve in cves:
                        cve_key = str(cve).upper()
                        self._vuln_cache[cve_key] = {
                            'qid': vuln.get('qid'),
                            'severity': vuln.get('severity'),
                            'cvss_base': vuln.get('cvss_base'),
                            'cvss_v3': vuln.get('cvss_v3'),
                            'title': vuln.get('title'),
                        }
                        updated += 1
                except Exception as e:
                    logger.debug(f"Error processing vulnerability: {e}")
                    continue

            # Persist to disk
            self._save()
            self.last_sync = time.time()
            self.error = None

            logger.info(f"Qualys sync complete: {updated} CVE mappings, {len(self._vuln_cache)} total cached")
            return {
                'synced': True,
                'count': len(self._vuln_cache),
                'mode': 'api',
                'fetched': len(vulns),
                'updated': updated,
            }

        except Exception as e:
            logger.error(f"Qualys sync failed: {e}")
            self.error = str(e)
            return {'synced': False, 'error': self.error}

    async def get_vulnerability_for_cve(self, cve: str) -> Dict[str, Any] | None:
        """Get vulnerability data for a specific CVE from local cache."""
        try:
            cve_key = str(cve).upper()
            return self._vuln_cache.get(cve_key)
        except Exception:
            return None

    async def get_vulnerabilities_for_cves(self, cves: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get vulnerability data for multiple CVEs from local cache."""
        out: dict[str, Dict[str, Any]] = {}
        for cve in cves or []:
            try:
                cve_key = str(cve).upper()
                if cve_key in self._vuln_cache:
                    out[cve_key] = self._vuln_cache[cve_key]
            except Exception:
                continue
        return out

    async def close(self) -> None:
        """Close HTTP client and cleanup resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
            logger.debug("Qualys HTTP client closed")


CLIENT = QualysClient()

__all__ = ['CLIENT', 'QualysClient']

