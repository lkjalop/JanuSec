from __future__ import annotations

import re
from typing import Any, Dict, Set


EMAIL_RE = re.compile(r"^[\w\.-]+@[\w\.-]+\.[A-Za-z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def classify_pii(ev: Dict[str, Any]) -> Set[str]:
    tags: Set[str] = set()
    try:
        for k, v in ev.items():
            if not isinstance(v, (str, int, float)):
                continue
            s = str(v)
            if EMAIL_RE.match(s):
                tags.add('pii:email')
            if IP_RE.match(s):
                tags.add('pii:ip')
    except Exception:
        pass
    return tags

