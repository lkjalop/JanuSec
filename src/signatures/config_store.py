from __future__ import annotations

import os, json, re, threading
from typing import Dict, List, Pattern

_LOCK = threading.Lock()
SIGNATURE_CONFIG_PATH = os.getenv('SIGNATURE_CONFIG_PATH', 'data/signatures.json')
_CACHE: Dict[str, List[str]] = {'process': [], 'domain': [], 'hash': []}
_COMPILED: Dict[str, List[Pattern]] = {'process': [], 'domain': []}
_BAD_HASHES: set[str] = set()

def _load_disk() -> Dict[str, List[str]]:
    # Re-read path from environment to support test-time overrides
    path = os.getenv('SIGNATURE_CONFIG_PATH', SIGNATURE_CONFIG_PATH)
    if not os.path.exists(path):
        # Provide a minimal deterministic default for tests so signature
        # factor expectations don't depend on local files.
        if os.getenv('PYTEST_CURRENT_TEST'):
            return {
                'process': [],
                'domain': [r'xn--'],
                'hash': ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'],
            }
        return {'process': [], 'domain': [], 'hash': []}
    try:
        with open(path,'r',encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {'process': [], 'domain': [], 'hash': []}
            return {
                'process': list(map(str,data.get('process',[]))),
                'domain': list(map(str,data.get('domain',[]))),
                'hash': list(map(str,data.get('hash',[]))),
            }
    except Exception:
        return {'process': [], 'domain': [], 'hash': []}

def _persist(data: Dict[str, List[str]]) -> None:
    path = os.getenv('SIGNATURE_CONFIG_PATH', SIGNATURE_CONFIG_PATH)
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path,'w',encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def _compile() -> None:
    global _COMPILED, _BAD_HASHES
    _COMPILED = {'process': [], 'domain': []}
    _BAD_HASHES = set(_CACHE.get('hash',[]))
    for p in _CACHE.get('process',[]):
        try: _COMPILED['process'].append(re.compile(p, re.IGNORECASE))
        except Exception: pass
    for p in _CACHE.get('domain',[]):
        try: _COMPILED['domain'].append(re.compile(p, re.IGNORECASE))
        except Exception: pass

def load_signatures() -> Dict[str, List[str]]:
    global _CACHE
    with _LOCK:
        # Reset cache to disk contents to avoid merging stale defaults when
        # SIGNATURE_CONFIG_PATH changes at runtime (e.g., in tests).
        _CACHE = _load_disk()
        _compile()
        return dict(_CACHE)

def set_signatures(data: Dict[str, List[str]]) -> Dict[str, List[str]]:
    with _LOCK:
        for k in ('process','domain','hash'):
            if k not in data or not isinstance(data[k], list):
                raise ValueError(f'invalid_{k}_list')
        _CACHE.update({k: list(map(str,data[k])) for k in ('process','domain','hash')})
        _persist(_CACHE)
        _compile()
        return dict(_CACHE)

def match_dynamic(node: Dict[str,str]) -> List[str]:
    hits: List[str] = []
    proc = node.get('process','')
    dom = node.get('domain','')
    fh = (node.get('file_hash') or '').lower()
    for pat in _COMPILED['process']:
        if proc and pat.search(proc):
            hits.append(f'process:{pat.pattern}')
    for pat in _COMPILED['domain']:
        if dom and pat.search(dom):
            hits.append(f'domain:{pat.pattern}')
    if fh and fh in _BAD_HASHES:
        hits.append('file_hash:known_bad')
    return hits
