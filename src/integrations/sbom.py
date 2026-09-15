"""Simple SBOM lookup helper.

This module implements a lightweight local cache that maps binary sha256 or
image digest -> SBOM components -> CVE list -> CVSS/KEV/EPSS metadata.

For demo purposes the SBOM store is a JSON file at `data/sbom_cache.json` if present.
The public API is best-effort and returns empty lists when data is missing.
"""
from __future__ import annotations

import json, os
from pathlib import Path
from typing import Dict, Any, List, Optional

DEFAULT_PATH = Path(os.getenv('SBOM_CACHE_FILE', 'data/sbom_cache.json'))


class SBOMLookup:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else DEFAULT_PATH
        self._cache: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                self._cache = json.loads(self.path.read_text(encoding='utf-8'))
        except Exception:
            self._cache = {}

    def lookup_binary(self, sha256: str) -> Dict[str, Any]:
        """Lookup by binary sha256. Returns dict with keys: components, cves ([{cve,cvss,kev,epss}])."""
        if not sha256:
            return {'components': [], 'cves': []}
        try:
            entry = self._cache.get(sha256.lower()) or {}
            comps = entry.get('components') or []
            cves = entry.get('cves') or []
            return {'components': comps, 'cves': cves}
        except Exception:
            return {'components': [], 'cves': []}

    def lookup_image(self, digest: str) -> Dict[str, Any]:
        # same as binary lookup for now
        return self.lookup_binary(digest)


GLOBAL_SBOM = SBOMLookup()

__all__ = ['GLOBAL_SBOM']
