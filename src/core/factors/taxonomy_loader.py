from __future__ import annotations
import json, os, threading
from typing import Dict, Any

_TAXONOMY_PATH = os.getenv('FACTOR_TAXONOMY_PATH','data/factors_taxonomy.json')
_CACHE: Dict[str, Any] | None = None
_LOCK = threading.RLock()

def load_taxonomy() -> Dict[str, Any]:
    global _CACHE
    with _LOCK:
        if _CACHE is not None:
            return _CACHE
        try:
            with open(_TAXONOMY_PATH,'r',encoding='utf-8') as fh:
                _CACHE = json.load(fh)
        except Exception:
            _CACHE = {'domains':[], 'factors':[]}
        return _CACHE

def factor_index() -> Dict[str, Dict[str, Any]]:
    tax = load_taxonomy()
    out: Dict[str, Dict[str, Any]] = {}
    for f in tax.get('factors', []):
        name = f.get('name')
        if name:
            out[name] = f
    return out

def domain_for_factor(name: str) -> str | None:
    return factor_index().get(name, {}).get('domain')

def precedence_for_factor(name: str) -> int | None:
    val = factor_index().get(name, {}).get('precedence')
    return int(val) if isinstance(val, (int, float)) else None

__all__ = ['load_taxonomy','factor_index','domain_for_factor','precedence_for_factor']
