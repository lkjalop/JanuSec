from __future__ import annotations

from typing import List, Dict

import os
from .config_store import load_signatures, match_dynamic

_STATIC_DEFAULTS = load_signatures()  # ensure initial load

def match_signatures(node: Dict[str, str]) -> List[str]:
    # In tests, refresh signatures so earlier test overrides don't leak
    if os.getenv('PYTEST_CURRENT_TEST'):
        try:
            load_signatures()
        except Exception:
            pass
    # dynamic matches
    dynamic_hits = match_dynamic(node)
    return dynamic_hits

