"""Lightweight shim for Threat Intel client used by tests.

Provides a global `CLIENT` with minimal behavior: an in-memory store
of IPs/domains/hashes and simple lookup APIs. This is a test shim and
intended to be sufficient for local pytest runs.
"""
from __future__ import annotations
import time
from typing import Dict, Set


class _ShimClient:
    def __init__(self):
        self.enabled = True
        self._ips: Dict[str, float] = {}
        self._domains: Dict[str, float] = {}
        self._hashes: Dict[str, float] = {}
        self._current_origin = 'shim'
        # Optional metadata used by intel endpoints
        self._failure_streak: Dict[str, int] = {}
        self._confidence: Dict[str, Dict[str, float]] = {}
        self._origins: Dict[str, Dict[str, str]] = {}
        self.sync_interval = 900
        # Per-(tenant,feed) enabled state for the /feeds/{feed}/toggle endpoint.
        self.feed_enabled: Dict[str, Dict[str, bool]] = {}
        # MITRE technique attribution: factor -> [techniques]; and provenance
        # factor -> technique -> {source feeds}. Populated by enrichment in prod;
        # exposed via /techniques/provenance.
        self.factor_techniques: Dict[str, list] = {}
        self._technique_provenance: Dict[str, Dict[str, set]] = {}

    def _add_ip(self, ip: str, ttl_hours: int = 24) -> None:
        self._ips[ip] = time.time() + float(ttl_hours) * 3600.0

    def _add_domain(self, d: str, ttl_hours: int = 24) -> None:
        self._domains[d] = time.time() + float(ttl_hours) * 3600.0

    def _add_hash(self, h: str, ttl_hours: int = 24) -> None:
        self._hashes[h] = time.time() + float(ttl_hours) * 3600.0

    def _prune(self) -> None:
        now = time.time()
        for m in (self._ips, self._domains, self._hashes):
            for k in list(m.keys()):
                if m.get(k, 0) < now:
                    m.pop(k, None)

    # Exposed mapping-like attributes expected by intel_endpoints
    @property
    def ip_set(self):
        return set(self._ips.keys())

    @property
    def ip_ttl(self):
        return dict(self._ips)

    @property
    def domain_set(self):
        return set(self._domains.keys())

    @property
    def domain_ttl(self):
        return dict(self._domains)

    @property
    def hash_set(self):
        return set(self._hashes.keys())

    @property
    def hash_ttl(self):
        return dict(self._hashes)

    # Provide other sets as empty by default for compatibility
    @property
    def url_set(self):
        return set()

    @property
    def url_ttl(self):
        return {}

    @property
    def ja3_set(self):
        return set()

    @property
    def ja3_ttl(self):
        return {}

    @property
    def certfp_set(self):
        return set()

    @property
    def certfp_ttl(self):
        return {}

    # Confidence/origin helpers
    def ioc_confidence(self, ioc_type: str, value: str) -> float:
        # Return 1.0 if present, otherwise 0.0
        try:
            v = value.lower()
        except Exception:
            v = value
        if ioc_type == 'ip' and v in self._ips:
            return 1.0
        if ioc_type == 'domain' and v in self._domains:
            return 1.0
        if ioc_type == 'hash' and v in self._hashes:
            return 1.0
        return 0.0

    def origin_for(self, value: str) -> str | None:
        # Return the current origin if we have the value; else None
        try:
            v = value.lower()
        except Exception:
            v = value
        if v in self._ips or v in self._domains or v in self._hashes:
            return getattr(self, '_current_origin', None)
        return None

    def is_malicious_ip(self, ip: str) -> bool:
        self._prune()
        return ip in self._ips

    def is_malicious_domain(self, domain: str) -> bool:
        self._prune()
        return domain in self._domains

    def is_malicious_hash(self, h: str) -> bool:
        self._prune()
        return h in self._hashes

    def status(self) -> dict:
        return {'enabled': self.enabled, 'num_ips': len(self._ips), 'origin': self._current_origin}

    async def sync_now(self, source: str) -> dict:
        # Test stub: pretend to sync and return a small summary
        return {'synced': True, 'created': []}

    # Feed enable/disable, keyed per tenant ('*' = global default).
    def set_feed_enabled(self, feed: str, enabled: bool, tenant_id: str | None = None) -> bool:
        key = tenant_id or '*'
        self.feed_enabled.setdefault(key, {})[feed] = bool(enabled)
        return bool(enabled)

    def is_feed_enabled(self, feed: str, tenant_id: str | None = None) -> bool:
        key = tenant_id or '*'
        per = self.feed_enabled.get(key) or self.feed_enabled.get('*') or {}
        return bool(per.get(feed, True))

    # JSON-serializable view of technique provenance (sets -> sorted lists).
    def technique_provenance(self) -> Dict[str, Dict[str, list]]:
        out: Dict[str, Dict[str, list]] = {}
        for factor, techs in self._technique_provenance.items():
            out[factor] = {t: sorted(srcs) for t, srcs in (techs or {}).items()}
        return out

    # Circuit-breaker-guarded HTTP GET for feed fetches. Returns the response on
    # success, None on a network error (after recording the failure), and raises
    # circuit_open once the breaker has tripped.
    async def _http_get(self, url: str):
        import os
        from core.net.circuit_breaker import get_circuit
        cb = get_circuit('intel_http')
        # Honor a live CB_FAILURE_THRESHOLD even if the breaker was cached earlier.
        try:
            cb.failure_threshold = int(os.getenv('CB_FAILURE_THRESHOLD', cb.failure_threshold) or cb.failure_threshold)
        except Exception:
            pass
        if cb.is_open():
            raise RuntimeError(f'circuit_open:{cb.name}')
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                return await client.get(url)
        except Exception:
            await cb.record_failure()
            return None


CLIENT = _ShimClient()

__all__ = ['CLIENT']
