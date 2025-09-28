"""SBOM Repository (in-memory MVP)

Stores parsed SBOM components per tenant. Future: move to persistent store.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
import threading, time

@dataclass
class SBOMComponent:
    name: str
    version: str | None
    purl: str | None
    hashes: Dict[str,str]
    licenses: List[str]
    first_seen: float
    last_seen: float

class SBOMRepository:
    def __init__(self):
        self._lock = threading.Lock()
        # tenant -> (component_key -> SBOMComponent)
        self._store: Dict[str, Dict[str, SBOMComponent]] = {}

    def upsert_components(self, tenant: str, comps: List[SBOMComponent]):
        now = time.time()
        with self._lock:
            bucket = self._store.setdefault(tenant, {})
            for c in comps:
                key = f"{c.name}:{c.version or 'unknown'}"
                existing = bucket.get(key)
                if existing:
                    existing.last_seen = now
                    # merge hashes/licenses
                    existing.hashes.update(c.hashes)
                    for lic in c.licenses:
                        if lic not in existing.licenses:
                            existing.licenses.append(lic)
                else:
                    bucket[key] = c

    def list_components(self, tenant: str, limit: int = 200) -> List[SBOMComponent]:
        with self._lock:
            bucket = self._store.get(tenant, {})
            return list(bucket.values())[:limit]

_sbom_singleton: SBOMRepository | None = None

def get_sbom_repo() -> SBOMRepository:
    global _sbom_singleton
    if _sbom_singleton is None:
        _sbom_singleton = SBOMRepository()
    return _sbom_singleton
