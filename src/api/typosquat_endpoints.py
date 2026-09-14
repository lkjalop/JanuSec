from __future__ import annotations

from fastapi import APIRouter, Query
from typing import Dict, Any

router = APIRouter(prefix="/api/v1/email", tags=["email-security"])

def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    dp = [[0]*(len(b)+1) for _ in range(len(a)+1)]
    for i in range(len(a)+1): dp[i][0] = i
    for j in range(len(b)+1): dp[0][j] = j
    for i in range(1,len(a)+1):
        for j in range(1,len(b)+1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
    return dp[-1][-1]

@router.get('/typosquat')
def typosquat(domain: str = Query(...), against: str = Query(...)) -> Dict[str, Any]:
    dist = _levenshtein(domain.lower(), against.lower())
    # Simple heuristic: distance 1-2 and length >=6 -> flag
    factor = None
    if len(domain) >= 6 and len(against) >= 6 and 0 < dist <= 2:
        factor = 'email:typosquat_domain'
    return {'domain': domain, 'against': against, 'distance': dist, 'factor': factor}

__all__ = ['router']