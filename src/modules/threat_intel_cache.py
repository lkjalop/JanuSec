from __future__ import annotations

import os
import time
from typing import Any
try:  # pragma: no cover - optional redis
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore


class ThreatIntelCache:
    """Threat Intel Cache with optional MISP/OpenCTI sync stubs.

    In production, this would maintain IoC sets and actor/technique mappings.
    Here we provide lightweight in-memory structures and stubbed sync methods
    so callers and tests can exercise the paths without heavy dependencies.
    
    DEPRECATED: This module is superseded by integrations.threat_intel_client.ThreatIntelClient.
    All new code should import CLIENT from that module. This class remains to avoid
    breaking existing imports until fully removed.
    """

    def __init__(self, config):
        self.config = config
        self.iocs: set[str] = set()
        self.actors: dict[str, dict[str, Any]] = {}
        self.techniques: dict[str, dict[str, Any]] = {}
        self.last_sync: dict[str, float] = {}
        self._redis = None
        url = os.getenv('REDIS_URL')
        if url and redis is not None:
            try:
                self._redis = redis.Redis.from_url(url, decode_responses=True)
            except Exception:
                self._redis = None

    async def initialize(self):
        return

    async def health_check(self):
        return True

    async def shutdown(self):
        return

    # ---------------------- Sync Stubs ----------------------
    async def sync_misp(self) -> dict[str, Any]:
        url = os.getenv('MISP_URL')
        key = os.getenv('MISP_KEY')
        # simulate import of a handful of IoCs
        if url and key:
            new = {'1.2.3.4', 'evil.example.com', '44d88612fea8a8f36de82e1278abb02f'}
            self.iocs.update(new)
            if self._redis:
                try:
                    self._redis.sadd('intel:iocs', *list(new))
                except Exception:
                    pass
            self.last_sync['misp'] = time.time()
            return {'source': 'misp', 'iocs_added': 3, 'synced': True}
        return {'source': 'misp', 'synced': False, 'error': 'not_configured'}

    async def sync_opencti(self) -> dict[str, Any]:
        url = os.getenv('OPENCTI_URL')
        token = os.getenv('OPENCTI_TOKEN')
        if url and token:
            # simulate actor/technique enrichment catalog
            self.actors['APT-XYZ'] = {'aliases': ['Group-XYZ'], 'score': 0.8}
            self.techniques['T1059'] = {'name': 'Command and Scripting Interpreter'}
            if self._redis:
                try:
                    self._redis.hset('intel:actors', mapping={'APT-XYZ': 'Group-XYZ'})
                    self._redis.hset('intel:techniques', mapping={'T1059': 'Command and Scripting Interpreter'})
                except Exception:
                    pass
            self.last_sync['opencti'] = time.time()
            return {'source': 'opencti', 'actors_added': 1, 'techniques_added': 1, 'synced': True}
        return {'source': 'opencti', 'synced': False, 'error': 'not_configured'}

    # ---------------------- Queries -------------------------
    def match_ioc(self, token: str) -> bool:
        # Delegate to new client if present
        try:
            from integrations.threat_intel_client import CLIENT as _TI  # type: ignore
            if getattr(_TI, 'match_ioc', None):
                return bool(_TI.match_ioc(token))
        except Exception:
            pass
        key = str(token).strip().lower()
        if key in self.iocs:
            return True
        if self._redis:
            try:
                return bool(self._redis.sismember('intel:iocs', key))
            except Exception:
                return False
        return False

    def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        out = dict(event)
        # naive enrichment: add actor tag if user agent contains sample string
        ua = str(event.get('http_user_agent') or '').lower()
        if 'cobalt' in ua:
            out.setdefault('tags', []).append('actor:APT-XYZ')
        return out

_CACHE: ThreatIntelCache | None = None


def get_threat_intel_cache(config: dict | None = None) -> ThreatIntelCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = ThreatIntelCache(config or {})
    return _CACHE


__all__ = ['ThreatIntelCache', 'get_threat_intel_cache']