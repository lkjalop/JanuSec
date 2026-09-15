from __future__ import annotations
import os, hashlib, json
from typing import Optional
from pathlib import Path

_STORE = {}
_STORE_PATH = Path(os.getenv('PSEUDO_STORE','data/pseudomap.json'))


def _load():
    global _STORE
    try:
        if _STORE_PATH.exists():
            _STORE = json.loads(_STORE_PATH.read_text(encoding='utf-8'))
    except Exception:
        _STORE = {}


def _save():
    try:
        _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STORE_PATH.write_text(json.dumps(_STORE, indent=2), encoding='utf-8')
    except Exception:
        pass


def pseudonymize(value: str) -> str:
    _load()
    if value in _STORE:
        return _STORE[value]
    h = hashlib.sha256(value.encode()).hexdigest()
    pid = f'pseudo:{h[:12]}'
    _STORE[value] = pid
    _save()
    return pid


def deanonymize(pid: str) -> Optional[str]:
    _load()
    for k, v in _STORE.items():
        if v == pid:
            return k
    return None
