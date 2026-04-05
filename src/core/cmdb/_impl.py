from __future__ import annotations

"""Internal CMDB mock implementation.

Provides a small, deterministic in-memory CMDB client used by tests and
local development. Kept intentionally minimal so it can be safely imported
during test collection and CI runs.
"""

import time
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple


@dataclass
class AssetRecord:
    asset_id: str
    hostname: Optional[str]
    ip: Optional[str]
    business_unit: Optional[str]
    criticality: float
    owner: Optional[str]
    tags: List[str]
    network_zone: Optional[str]
    public_exposed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'asset_id': self.asset_id,
            'hostname': self.hostname,
            'ip': self.ip,
            'business_unit': self.business_unit,
            'criticality': self.criticality,
            'owner': self.owner,
            'tags': self.tags,
            'network_zone': self.network_zone,
            'public_exposed': self.public_exposed,
        }


class BaseCMDBClient:
    """Abstract interface for CMDB clients."""

    def lookup(self, *, ip: Optional[str] = None, hostname: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[AssetRecord]:
        raise NotImplementedError()


class MockCMDBClient(BaseCMDBClient):
    """Thread-safe in-memory mock client used in tests."""

    def __init__(self, seed: Optional[Dict[str, AssetRecord]] = None, cache_ttl: int = 3600):
        self._seed = seed or {}
        self._by_asset = {k: v for k, v in self._seed.items()}
        self._by_ip = {v.ip: v for v in self._seed.values() if v.ip}
        self._by_hostname = {v.hostname: v for v in self._seed.values() if v.hostname}
        self._cache: Dict[str, Tuple[float, AssetRecord]] = {}
        self._cache_ttl = cache_ttl
        self._lock = threading.RLock()

    def _cache_get(self, key: str) -> Optional[AssetRecord]:
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            ts, rec = entry
            if time.time() - ts > self._cache_ttl:
                try:
                    del self._cache[key]
                except Exception:
                    pass
                return None
            return rec

    def _cache_set(self, key: str, rec: AssetRecord) -> None:
        with self._lock:
            self._cache[key] = (time.time(), rec)

    def lookup(self, *, ip: Optional[str] = None, hostname: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[AssetRecord]:
        key = asset_id or ip or hostname
        if not key:
            return None
        cached = self._cache_get(key)
        if cached:
            return cached
        rec: Optional[AssetRecord] = None
        if asset_id and asset_id in self._by_asset:
            rec = self._by_asset[asset_id]
        elif ip and ip in self._by_ip:
            rec = self._by_ip[ip]
        elif hostname and hostname in self._by_hostname:
            rec = self._by_hostname[hostname]
        if rec:
            self._cache_set(key, rec)
        return rec


def get_cmdb_client() -> BaseCMDBClient:
    seed = {
        'srv-001': AssetRecord('srv-001', 'db-srv-1', '10.0.0.5', 'Payments', 8.0, 'alice@example.com', ['db', 'payments'], 'prod', False),
        'fw-001': AssetRecord('fw-001', 'fw-1.example', '198.51.100.5', 'Infra', 6.0, 'ops@example.com', ['fw', 'edge'], 'perimeter', True),
    }
    return MockCMDBClient(seed=seed, cache_ttl=3600)


__all__ = ['AssetRecord', 'BaseCMDBClient', 'MockCMDBClient', 'get_cmdb_client']
