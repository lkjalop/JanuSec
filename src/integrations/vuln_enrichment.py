from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Set


class VulnEnricher:
    """Enriches CVEs with CISA KEV and EPSS scores.

    Network fetch is optional and controlled by VULN_ENRICH_ENABLED. Results are cached to disk.
    """

    def __init__(self) -> None:
        self.enabled = os.getenv('VULN_ENRICH_ENABLED', '1').lower() not in {'0','false','no'}
        self.kev_url = os.getenv('KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        self.epss_url = os.getenv('EPSS_URL', 'https://api.first.org/data/v1/epss')
        self.cache_dir = Path(os.getenv('VULN_ENRICH_CACHE_DIR', 'data/vuln_enrich_cache'))
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        self._kev_set: Set[str] = set()
        self._kev_last = 0.0
        self._kev_ttl = int(os.getenv('KEV_CACHE_TTL_SECONDS', '43200') or 43200)  # 12h
        self._epss_map: Dict[str, float] = {}
        self._epss_last = 0.0
        self._epss_ttl = int(os.getenv('EPSS_CACHE_TTL_SECONDS', '10800') or 10800)  # 3h
        # Conditional headers
        self._kev_etag = None
        self._kev_modified = None

    def _read_cache(self, name: str) -> Any:
        p = self.cache_dir / name
        try:
            if p.exists():
                return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return None
        return None

    def _write_cache(self, name: str, data: Any) -> None:
        p = self.cache_dir / name
        try:
            p.write_text(json.dumps(data), encoding='utf-8')
        except Exception:
            pass

    async def _http_get_json(self, url: str, headers: Dict[str,str] | None = None) -> Any:
        # Lazy import to avoid hard dep
        try:
            import httpx  # type: ignore
        except Exception:
            return None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(url, headers=headers or {})
                if r.status_code == 304:
                    return ''  # signal not-modified
                if r.status_code >= 400:
                    return None
                return r.json()
        except Exception:
            return None

    async def refresh_kev(self) -> None:
        if not self.enabled:
            return
        now = time.time()
        if (now - self._kev_last) < self._kev_ttl and self._kev_set:
            return
        # Try cache first
        cached = self._read_cache('kev.json')
        if cached and isinstance(cached, dict) and 'cve_set' in cached:
            self._kev_set = set(cached.get('cve_set') or [])
            self._kev_last = cached.get('ts') or now
        # Fetch remote if allowed
        headers = {}
        if self._kev_etag:
            headers['If-None-Match'] = self._kev_etag
        if self._kev_modified:
            headers['If-Modified-Since'] = self._kev_modified
        data = await self._http_get_json(self.kev_url, headers=headers) if self.enabled else None
        if data == '':
            # not modified
            self._kev_last = now
            return
        if isinstance(data, dict):
            # The CISA KEV feed schema has a 'vulnerabilities' array with 'cveID'
            vulns = data.get('vulnerabilities') or []
            kev = set()
            for it in vulns:
                cve = (it or {}).get('cveID') or (it or {}).get('cve')
                if isinstance(cve, str):
                    kev.add(cve.strip().upper())
            self._kev_set = kev
            self._kev_last = now
            # Save cache
            self._write_cache('kev.json', {'cve_set': sorted(list(kev)), 'ts': now})

    async def refresh_epss(self, cves: List[str]) -> None:
        if not self.enabled or not cves:
            return
        now = time.time()
        # If recent and have scores for all cves, skip
        if (now - self._epss_last) < self._epss_ttl:
            missing = [c for c in cves if c.upper() not in self._epss_map]
            if not missing:
                return
        # Try cached map on disk
        cached = self._read_cache('epss.json')
        if isinstance(cached, dict) and 'scores' in cached and 'ts' in cached:
            self._epss_map.update({k.upper(): float(v) for k,v in (cached.get('scores') or {}).items()})
            self._epss_last = cached.get('ts') or now
        # Fetch remote (batch via comma-separated)
        try:
            base = self.epss_url
            qs = ','.join({x.upper() for x in cves})
            url = f"{base}?cve={qs}"
            data = await self._http_get_json(url)
            if isinstance(data, dict):
                # EPSS API returns data:[{cve, epss, percentile}]
                arr = data.get('data') or []
                for it in arr:
                    cve = (it or {}).get('cve')
                    sc = (it or {}).get('epss')
                    try:
                        if isinstance(cve, str) and sc is not None:
                            self._epss_map[cve.upper()] = float(sc)
                    except Exception:
                        continue
                self._epss_last = now
                self._write_cache('epss.json', {'scores': self._epss_map, 'ts': now})
        except Exception:
            return

    def _severity_weight(self, sev: str | None) -> float:
        s = (sev or '').lower()
        return {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.45,
            'low': 0.2,
        }.get(s, 0.3)

    async def enrich(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Collect CVEs to fetch EPSS
        cves = [str((v.get('cve') or '')).upper() for v in vulns if v.get('cve')]
        cves = [c for c in cves if c.startswith('CVE-')]
        if self.enabled:
            await self.refresh_kev()
            await self.refresh_epss(cves)
        out: List[Dict[str, Any]] = []
        for v in vulns:
            cve = str((v.get('cve') or '')).upper()
            sev = v.get('severity')
            kev = cve in self._kev_set if cve else False
            epss = float(self._epss_map.get(cve, 0.0)) if cve else 0.0
            exploit_available = bool(kev or (epss >= float(os.getenv('EPSS_EXPLOIT_THRESHOLD','0.7'))))
            # compute simple risk score
            base = self._severity_weight(sev)
            risk = base + (0.2 if kev else 0.0) + min(epss, 0.3)
            risk = min(1.0, round(risk, 3))
            nv = dict(v)
            nv['kev'] = kev
            nv['epss'] = round(epss, 4)
            nv['exploit_available'] = exploit_available
            nv['risk_score'] = risk
            out.append(nv)
        return out


# Singleton
ENRICHER = VulnEnricher()
