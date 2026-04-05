import re
from typing import List, Dict

PROMPT_INJECTION_PATTERNS = [
    r'ignore\s+(previous|prior)\s+instructions',
    r'you\s+are\s+now\s+in\s+(developer|admin|debug)\s+mode',
    r'output\s+raw\s+data',
    r'summarize\s+all\s+(api\s+keys|secrets|credentials)',
    r'forget\s+your\s+constraints',
]


def detect_prompt_injection(text: str) -> List[Dict]:
    out = []
    t = text.lower()
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, t):
            out.append({'pattern': pat, 'matched': True, 'score': 0.7})
    return out


__all__ = ['detect_prompt_injection']
