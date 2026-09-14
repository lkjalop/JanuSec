from __future__ import annotations

import re
from typing import Dict

# Very small CVSS vector parser for CVSS:3.1/AV:N/AC:L/... style
_kv_re = re.compile(r'([A-Z]{1,5}):([^/]+)')

def parse_cvss_vector(vec: str) -> Dict[str, str]:
    res = {}
    for m in _kv_re.finditer(vec):
        k = m.group(1)
        v = m.group(2)
        res[k] = v
    return res

def cvss_exploitability(parsed: Dict[str,str]) -> float:
    # naive scoring mapping
    av = {'N':0.85,'A':0.62,'L':0.55,'P':0.2}
    ac = {'L':0.77,'H':0.44}
    pr = {'N':0.85,'L':0.62,'H':0.27}
    ui = {'N':0.85,'R':0.62}
    try:
        score = av.get(parsed.get('AV','N'),0.62) * ac.get(parsed.get('AC','L'),0.77) * pr.get(parsed.get('PR','N'),0.85) * ui.get(parsed.get('UI','N'),0.85)
        return score
    except Exception:
        return 0.0
