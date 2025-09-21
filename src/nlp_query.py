"""NLP Query Module

Phase 3 foundation: natural language -> internal DSL -> data fetch.
This is intentionally lightweight & rule-based; can be extended with embeddings.
"""
from __future__ import annotations
import re
import datetime as dt
from typing import Dict, Any, Optional, List

TIME_PATTERNS = [
    (re.compile(r'last\s+(\d+)\s*h'), 'hours'),
    (re.compile(r'last\s+(\d+)\s*m'), 'minutes'),
]

# Simple intent keywords -> filters
VERDICT_MAP = {
    'malicious': 'malicious',
    'benign': 'benign',
    'suspicious': 'suspicious'
}

CONF_PATTERN = re.compile(r'confidence\s*(?:>|>=)\s*(0?\.\d+|1\.0|1)')

class ParsedQuery:
    def __init__(self, dsl: Dict[str, Any]):
        self.dsl = dsl

    def build(self, page: int = 1, size: int = 50):
        base = "SELECT event_id, verdict, confidence, processing_ms, factors, created_at FROM decisions"
        clauses = []
        params: List[Any] = []
        dsl = self.dsl
        if 'verdict' in dsl:
            clauses.append("verdict = $%d" % (len(params)+1))
            params.append(dsl['verdict'])
        if 'confidence_gt' in dsl:
            clauses.append("confidence > $%d" % (len(params)+1))
            params.append(dsl['confidence_gt'])
        if 'time_after' in dsl:
            clauses.append("created_at >= $%d" % (len(params)+1))
            params.append(dsl['time_after'])
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        offset = max(page-1,0) * size
        sql = f"{base}{where} ORDER BY created_at DESC LIMIT {size} OFFSET {offset}"
        return sql, params


def parse_nl(text: str) -> ParsedQuery:
    text_l = text.lower()
    dsl: Dict[str, Any] = { 'limit': 50 }

    # Verdict extraction
    for k,v in VERDICT_MAP.items():
        if k in text_l:
            dsl['verdict'] = v
            break

    # Confidence threshold
    m = CONF_PATTERN.search(text_l)
    if m:
        dsl['confidence_gt'] = float(m.group(1))

    # Time window
    now = dt.datetime.utcnow()
    for pat, unit in TIME_PATTERNS:
        m = pat.search(text_l)
        if m:
            qty = int(m.group(1))
            delta = dt.timedelta(**{unit: qty})
            dsl['time_after'] = (now - delta).isoformat()
            break

    # Regex factor mention (naive)
    if 'regex' in text_l:
        dsl['hint_regex_factor'] = True

    return ParsedQuery(dsl)

# Semantic factor search stub; returns empty until extended
async def semantic_factor_search(factor_phrase: str, top_k: int = 5) -> List[str]:
    # Future: embed phrase & compare against stored factor embeddings
    return []
