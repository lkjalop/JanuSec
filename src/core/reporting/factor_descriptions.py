"""Factor Descriptions Loader"""
from __future__ import annotations

import functools
import json
import os
from typing import Dict


@functools.lru_cache(maxsize=1)
def load_factor_descriptions() -> dict[str,str]:
    base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config')
    base_path = os.path.join(base_dir, 'factor_descriptions.json')
    ext_path = os.path.join(base_dir, 'factor_descriptions_ext.json')
    merged: dict[str, str] = {}
    try:
        with open(base_path, encoding='utf-8') as f:
            merged.update(json.load(f))
    except Exception:
        pass
    # Optional overlay to extend without touching the canonical file
    try:
        with open(ext_path, encoding='utf-8') as f:
            ext = json.load(f)
            if isinstance(ext, dict):
                merged.update(ext)
    except Exception:
        pass
    return merged

def describe_factor(f: str) -> str | None:
    return load_factor_descriptions().get(f)
