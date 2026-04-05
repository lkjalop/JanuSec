"""Lightweight in-memory Threat Hunting DSL.

Example:
    from hunt.dsl import Query, run_query
    results = Query().factors_contains('endpoint:rare_lineage').limit(25).execute(decisions)
"""
from __future__ import annotations

from typing import List, Dict, Any, Iterable

class Query:
    def __init__(self):
        self._factor_contains: List[str] = []
        self._user: str | None = None
        self._limit: int = 100

    def factors_contains(self, *names: str) -> 'Query':
        for n in names:
            if n and n not in self._factor_contains:
                self._factor_contains.append(n)
        return self

    def user(self, user: str) -> 'Query':
        self._user = user
        return self

    def limit(self, n: int) -> 'Query':
        self._limit = max(1, min(1000, n))
        return self

    def execute(self, decisions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for d in decisions:
            if len(out) >= self._limit:
                break
            try:
                if self._user and str(d.get('user')) != self._user:
                    continue
                dfactors = [f.get('name') or f.get('factor') for f in d.get('factors', []) if isinstance(f, dict)]
                if self._factor_contains and not any(f in dfactors for f in self._factor_contains):
                    continue
                out.append(d)
            except Exception:
                continue
        return out

def run_query(spec: Dict[str, Any], decisions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    q = Query()
    for f in spec.get('factors_contains', []) or []:
        q.factors_contains(str(f))
    if spec.get('user'):
        q.user(str(spec.get('user')))
    if spec.get('limit'):
        try:
            q.limit(int(spec.get('limit')))
        except Exception:
            pass
    return q.execute(decisions)

__all__ = ['Query','run_query']