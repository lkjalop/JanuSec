from __future__ import annotations

import json
import os
from copy import deepcopy
from typing import Any, Dict, Optional

_CACHE: Optional[Dict[str, Any]] = None
_CACHE_MTIME: float | None = None


def _load_contracts(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("invalid log pull contracts format")
    if "sources" not in data or not isinstance(data.get("sources"), dict):
        data["sources"] = {}
    return data


def load_contracts(force: bool = False) -> Dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    path = os.getenv("LOG_PULL_CONTRACTS_PATH", os.path.join("config", "log_pull_contracts.json"))
    try:
        mtime = os.path.getmtime(path)
    except Exception:
        mtime = None
    if not force and _CACHE is not None and mtime is not None and _CACHE_MTIME == mtime:
        return _CACHE
    try:
        data = _load_contracts(path)
    except Exception:
        data = {"version": "0.0", "updated": None, "sources": {}}
    _CACHE = data
    _CACHE_MTIME = mtime
    return data


def get_contract(source: str) -> Optional[Dict[str, Any]]:
    contracts = load_contracts()
    src = (source or "").strip()
    if not src:
        return None
    contract = contracts.get("sources", {}).get(src)
    if not contract:
        return None
    return deepcopy(contract)


def list_contracts() -> Dict[str, Any]:
    contracts = load_contracts()
    return deepcopy(contracts)

