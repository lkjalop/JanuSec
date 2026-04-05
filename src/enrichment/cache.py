"""Simple enrichment cache storing reputation lookups.
Provides get/set helpers for EPSS/KEV/ASN/CVE lookups.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, Optional

CACHE_DIR = Path('data') / 'enrichment_cache'
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def _path_for(key: str) -> Path:
    safe = key.replace('/', '_').replace(':', '_')
    return CACHE_DIR / f"{safe}.json"

def get(key: str) -> Optional[Dict[str, Any]]:
    p = _path_for(key)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None

def set_(key: str, value: Dict[str, Any]) -> None:
    p = _path_for(key)
    try:
        p.write_text(json.dumps(value), encoding='utf-8')
    except Exception:
        pass
