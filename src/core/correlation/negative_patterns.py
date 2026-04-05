"""Negative (benign) pattern library to highlight likely false-positive contexts.

Patterns: each entry includes:
  name: identifier
  match_factors: list[str] any must be present
  conditions: {hour_range?: [start,end]}

evaluate_negative(factors) -> list[str] (matched pattern names)
Best-effort; used to annotate explain output (does not suppress factors yet).
"""
from __future__ import annotations
import os, json, time
from pathlib import Path
from typing import List, Dict, Any

_NEG_PATH = os.getenv('NEGATIVE_PATTERNS_PATH','src/config/negative_patterns.json')

class NegativePatterns:
    def __init__(self, path: str = _NEG_PATH):
        self.path = path
        self.patterns: List[Dict[str, Any]] = []
        self._load()
    def _load(self):
        try:
            p = Path(self.path)
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding='utf-8'))
            self.patterns = list(data.get('patterns', []))
        except Exception:
            pass
    def evaluate(self, factors: List[str]) -> List[str]:
        out: List[str] = []
        hr_now = time.gmtime().tm_hour
        sf = set(factors)
        for pat in self.patterns:
            mf = pat.get('match_factors', [])
            if not any(f in sf for f in mf):
                continue
            cond = pat.get('conditions', {})
            hr = cond.get('hour_range')
            if hr and isinstance(hr, list) and len(hr)==2:
                if not (hr[0] <= hr_now <= hr[1]):
                    continue
            out.append(pat.get('name') or 'benign')
        return out

GLOBAL_NEGATIVE_PATTERNS = NegativePatterns()

__all__ = ['NegativePatterns','GLOBAL_NEGATIVE_PATTERNS']
