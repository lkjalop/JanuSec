"""Clean CMDB client implementation used by tests (avoid touching client.py).

This module supplies `AssetRecord`, `BaseCMDBClient`, `MockCMDBClient`,
and `get_cmdb_client()` for deterministic unit tests and local dev.
"""
from dataclasses import dataclass
from typing import Optional, Dict
import time
import threading


@dataclass
class AssetRecord:
    asset_id: str
    business_unit: Optional[str]
    criticality: float
    owner: Optional[str]
    tags: list[str]
    network_zone: Optional[str]
    public_exposed: bool
    hostname: Optional[str] = None
    ip: Optional[str] = None


class BaseCMDBClient:
    def lookup(self, *, ip: Optional[str] = None, hostname: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[AssetRecord]:
        raise NotImplementedError()


class MockCMDBClient(BaseCMDBClient):
    def __init__(self, seed: Optional[Dict[str, AssetRecord]] = None, cache_ttl: int = 3600, ttl_seconds: Optional[int] = None):
        # support legacy tests that pass `ttl_seconds`
        if ttl_seconds is not None:
            cache_ttl = ttl_seconds
        self._seed = seed or {}
        self._by_asset = {k: v for k, v in self._seed.items()}
        self._by_ip = {v.ip: v for v in self._seed.values() if getattr(v, 'ip', None)}
        self._by_hostname = {v.hostname: v for v in self._seed.values() if getattr(v, 'hostname', None)}
        self._cache = {}
        self._cache_ttl = cache_ttl
        self._ts_by_asset = {k: time.time() for k in self._by_asset.keys()}
        self._lock = threading.RLock()

    def add_asset(self, asset: AssetRecord, aliases: Optional[list] = None) -> None:
        if aliases is None:
            aliases = []
        ts = time.time()
        # record under canonical id and aliases
        self._by_asset[asset.asset_id] = asset
        self._ts_by_asset[asset.asset_id] = ts
        if asset.ip:
            self._by_ip[asset.ip] = asset
        if asset.hostname:
            self._by_hostname[asset.hostname] = asset
        for a in aliases:
            # store alias keys into by_asset map for simple lookup
            self._by_asset[a] = asset
            self._by_ip.setdefault(a, asset)
            self._by_hostname.setdefault(a, asset)

    def _expire_asset(self, asset_id: str) -> None:
        with self._lock:
            try:
                del self._ts_by_asset[asset_id]
            except Exception:
                pass
            for key, rec in list(self._by_asset.items()):
                if rec.asset_id == asset_id:
                    try:
                        del self._by_asset[key]
                    except Exception:
                        pass
            for key, rec in list(self._by_ip.items()):
                if rec.asset_id == asset_id:
                    try:
                        del self._by_ip[key]
                    except Exception:
                        pass
            for key, rec in list(self._by_hostname.items()):
                if rec.asset_id == asset_id:
                    try:
                        del self._by_hostname[key]
                    except Exception:
                        pass
            for key, (_ts, rec) in list(self._cache.items()):
                if getattr(rec, "asset_id", None) == asset_id:
                    try:
                        del self._cache[key]
                    except Exception:
                        pass

    def _cache_get(self, key):
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

    def _cache_set(self, key, rec):
        with self._lock:
            self._cache[key] = (time.time(), rec)

    def lookup(self, query: Optional[str] = None, *, ip: Optional[str] = None, hostname: Optional[str] = None, asset_id: Optional[str] = None):
        # Support positional `query` for convenience (tests use client.lookup("id"))
        if query:
            # allow query to be ip/hostname/asset_id in order
            key = query
        else:
            key = asset_id or ip or hostname
        if not key:
            return None
        cached = self._cache_get(key)
        if cached:
            return cached
        rec = None
        if key in self._by_asset:
            rec = self._by_asset[key]
        elif key in self._by_ip:
            rec = self._by_ip[key]
        elif key in self._by_hostname:
            rec = self._by_hostname[key]
        if rec:
            ts = self._ts_by_asset.get(rec.asset_id)
            if ts is not None and (time.time() - ts > self._cache_ttl):
                self._expire_asset(rec.asset_id)
                return None
        if rec:
            self._cache_set(key, rec)
        return rec


def get_cmdb_client():
    seed = {
        'srv-001': AssetRecord(asset_id='srv-001', business_unit='Payments', criticality=8.0, owner='alice@example.com', tags=['db','payments'], network_zone='prod', public_exposed=False, hostname='db-srv-1', ip='10.0.0.5'),
        'fw-001': AssetRecord(asset_id='fw-001', business_unit='Infra', criticality=6.0, owner='ops@example.com', tags=['fw','edge'], network_zone='perimeter', public_exposed=True, hostname='fw-1.example', ip='198.51.100.5'),
    }
    return MockCMDBClient(seed=seed, cache_ttl=3600)


__all__ = ['AssetRecord', 'BaseCMDBClient', 'MockCMDBClient', 'get_cmdb_client']
