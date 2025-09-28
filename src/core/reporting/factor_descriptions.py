"""Factor Descriptions Loader"""
from __future__ import annotations
import json, os, functools
from typing import Dict

@functools.lru_cache(maxsize=1)
def load_factor_descriptions() -> Dict[str,str]:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config', 'factor_descriptions.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def describe_factor(f: str) -> str | None:
    return load_factor_descriptions().get(f)
