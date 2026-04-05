from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any
import re

router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation"])

# Simple heuristic mappings. These mirror frontend remediation hints but are backend-native.
_NODE_ACTIONS: Dict[str, List[str]] = {
    'user': [
        'Reset credentials', 'Force MFA re-enrollment', 'Review recent privilege grants'
    ],
    'host': [
        'Isolate host from network', 'Collect triage artifact (memory, processes)', 'Run EDR full scan'
    ],
    'file_hash': [
        'Quarantine file', 'Submit to sandbox', 'Add hash to blocklist'
    ],
    'process': [
        'Capture command line history', 'Terminate suspicious process', 'Persist forensic copy of binary'
    ],
    'domain': [
        'Block domain at DNS/Proxy', 'Submit domain for threat intel enrichment'
    ],
    'ip': [
        'Block IP at perimeter', 'Check recent connection logs'
    ],
    'cloud': [
        'Review IAM role assumptions', 'Rotate exposed keys', 'Restrict overly broad policies'
    ],
    'email': [
        'Search mailboxes for malicious campaign', 'Initiate user security awareness follow-up'
    ],
    'service': [
        'Enable additional access logging', 'Review API key usage', 'Apply rate limiting / WAF rule'
    ],
}

_CRITICAL_NODES = {'file_hash','process','cloud','user'}
_HIGH_NODES = {'domain','host','ip'}

def _parse_path(path: str) -> List[str]:
    # Accept delimiters '->', '|' or '>' and trim whitespace.
    if not path:
        return []
    # Normalize arrows to '->'
    raw = re.split(r"\s*(?:->|\|>|:)\s*", path.strip())
    return [p for p in raw if p]

def _infer_node_type(node: str) -> str:
    n = node.lower()
    # Heuristics based on value shape
    if '@' in n and '.' in n:
        return 'email'
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", n):
        return 'file_hash'
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", n):
        return 'ip'
    if '.' in n and len(n) <= 64 and not n.startswith('session:'):
        return 'domain'
    if any(x in n for x in ('ec2','vm','host','srv')):
        return 'host'
    if any(x in n for x in ('svc','service','api')):
        return 'service'
    if any(x in n for x in ('aws','azure','gcp','iam','cloud')):
        return 'cloud'
    if any(x in n for x in ('proc','cmd','exe','process')):
        return 'process'
    if any(x in n for x in ('user','acct','login')):
        return 'user'
    return 'host' if len(n) < 32 else 'service'

def _score_severity(types: List[str]) -> str:
    crit = sum(t in _CRITICAL_NODES for t in types)
    high = sum(t in _HIGH_NODES for t in types)
    if crit >= 2 or (crit >=1 and high >=2):
        return 'critical'
    if crit >=1 or high >=3:
        return 'high'
    if high >=1 or len(types) >=3:
        return 'medium'
    return 'low'

@router.get('/suggest')
async def remediation_suggest(path: str = Query(..., description="Chain of entities (e.g. user->host->file_hash)")) -> Dict[str, Any]:
    nodes = _parse_path(path)
    if not nodes:
        raise HTTPException(status_code=400, detail='empty_path')
    types = [_infer_node_type(n) for n in nodes]
    severity = _score_severity(types)
    actions: List[str] = []
    rationale: List[str] = []
    for t, n in zip(types, nodes):
        mapped = _NODE_ACTIONS.get(t, [])
        # choose top 2 per node type to avoid overload
        for act in mapped[:2]:
            actions.append(act)
        rationale.append(f"{n} classified as {t}; recommend {', '.join(mapped[:2]) if mapped else 'further investigation'}")
    # Deduplicate while preserving order
    seen = set()
    dedup_actions = []
    for a in actions:
        if a not in seen:
            dedup_actions.append(a); seen.add(a)
    return {
        'path': path,
        'nodes': nodes,
        'types': types,
        'severity': severity,
        'actions': dedup_actions,
        'rationale': rationale,
        'suggested_count': len(dedup_actions)
    }
