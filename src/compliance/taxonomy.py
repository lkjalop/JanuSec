from __future__ import annotations

import json, os, time
from pathlib import Path
from typing import Any, Dict, List

_CACHE: Dict[str, Any] | None = None
_CACHE_MTIME: float = 0.0

def _taxonomy_path() -> Path:
    return Path(os.getenv('FACTORS_TAXONOMY_PATH', 'mappings/factors_taxonomy.json'))

def load_taxonomy(refresh: bool = False) -> Dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    path = _taxonomy_path()
    if _CACHE is None or refresh:
        try:
            with open(path, 'r', encoding='utf8') as fh:
                _CACHE = json.load(fh)
            _CACHE_MTIME = path.stat().st_mtime
        except Exception:
            _CACHE = {"version":0, "factors":[], "frameworks": []}
            _CACHE_MTIME = time.time()
    return _CACHE

def get_factors() -> List[Dict[str, Any]]:
    return list(load_taxonomy().get('factors', []))

def coverage(framework: str) -> Dict[str, Any]:
    data = load_taxonomy()
    factors = data.get('factors', [])
    total = len(factors)
    mapped_keys: List[str] = []
    unmapped_keys: List[str] = []
    for f in factors:
        val = f.get(framework)
        if val is None or (isinstance(val, str) and val.strip() == ''):
            unmapped_keys.append(f.get('key'))
        else:
            mapped_keys.append(f.get('key'))
    pct = (len(mapped_keys) / total * 100.0) if total else 0.0
    return {
        'framework': framework,
        'total_factors': total,
        'mapped': len(mapped_keys),
        'coverage_percent': round(pct, 2),
        'unmapped_factors': unmapped_keys,
        'sample_mapped': mapped_keys[:10],
        'taxonomy_version': data.get('version'),
        'generated': data.get('generated'),
        'cache_mtime': _CACHE_MTIME,
    }
