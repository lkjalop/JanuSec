import re
from typing import Dict, List, Any

LEGITIMATE_PACKAGES = {
    'lodash', 'express', 'react', 'axios', 'requests', 'flask', 'django'
}

TYPO_DISTANCE_THRESHOLD = 2

SUSPICIOUS_INSTALL_PATTERNS = [
    r'curl.*\|\s*bash',
    r'wget.*\|\s*sh',
    r'eval\s*\(',
    r'process\.env\[',
    r'fs\.readFileSync.*\.ssh',
    r'require\(["\']child_process',
]

SUSPICIOUS_TLDS = [r'\.tk$', r'\.ml$', r'\.ga$']


def _levenshtein(a: str, b: str) -> int:
    # simple DP
    if a == b:
        return 0
    la, lb = len(a), len(b)
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[la][lb]


def detect_typosquat(name: str) -> Dict[str, Any]:
    name_l = name.lower()
    for legit in LEGITIMATE_PACKAGES:
        d = _levenshtein(name_l, legit)
        if 0 < d <= TYPO_DISTANCE_THRESHOLD:
            return {"factor": "supply_chain:typosquat", "package": name, "score": 0.35, "hint": f"similar_to:{legit}"}
    return {}


def detect_suspicious_install_scripts(script_text: str) -> List[Dict[str, Any]]:
    out = []
    if not script_text:
        return out
    for pat in SUSPICIOUS_INSTALL_PATTERNS:
        if re.search(pat, script_text, re.IGNORECASE):
            out.append({"factor": "supply_chain:script_abuse", "score": 0.25, "pattern": pat})
    for tld in SUSPICIOUS_TLDS:
        if re.search(tld, script_text, re.IGNORECASE):
            out.append({"factor": "supply_chain:suspicious_tld_in_install", "score": 0.15, "pattern": tld})
    return out


def detect_network_calls_during_install(network_hosts: List[str]) -> Dict[str, Any]:
    if not network_hosts:
        return {}
    suspicious = [h for h in network_hosts if re.search(r'pastebin\.com|discord\.com|bit\.ly', h, re.IGNORECASE)]
    if suspicious:
        return {"factor": "supply_chain:exfil_tld", "score": 0.20, "hosts": suspicious}
    return {}


def verify_package(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a package payload and return supply-chain factors.

    Expected payload keys (best-effort):
      - name
      - version
      - ecosystem (npm|pypi|maven|rubygems|docker)
      - install_script (optional string)
      - observed_hosts (optional list of domains contacted during install)
    """
    name = payload.get('name', '')
    script = payload.get('install_script', '')
    observed = payload.get('observed_hosts', []) or []

    factors = []
    total_score = 0.0

    ty = detect_typosquat(name)
    if ty:
        factors.append(ty)
        total_score += ty.get('score', 0.0)

    for s in detect_suspicious_install_scripts(script):
        factors.append(s)
        total_score += s.get('score', 0.0)

    net = detect_network_calls_during_install(observed)
    if net:
        factors.append(net)
        total_score += net.get('score', 0.0)

    # Add a simple heuristic: unknown ecosystem + odd name
    eco = payload.get('ecosystem', '').lower()
    if eco and eco not in {'npm', 'pypi', 'maven', 'rubygems', 'docker'}:
        factors.append({"factor": "supply_chain:unknown_ecosystem", "score": 0.10, "ecosystem": eco})
        total_score += 0.10

    return {
        'package': {'name': name, 'version': payload.get('version')},
        'factors': factors,
        'score': min(total_score, 1.0),
        'verdict': 'suspicious' if total_score >= 0.25 else 'ok'
    }
