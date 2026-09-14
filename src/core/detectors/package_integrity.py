import re
from typing import Dict, List, Tuple, Any
import hashlib


class FactorResult(dict):
    """Backwards-compatible detector result.

    Older tests iterate directly over the detector return value expecting a list
    of factor objects. Newer callers expect a dict with ``factors`` and metadata.
    """

    def __iter__(self):
        return iter(self.get('factors', []))

def _sha256(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode('utf-8', errors='ignore'))
    return h.hexdigest()


SUSPICIOUS_INSTALL_PATTERNS = [
    r'curl .*\|\s*bash',
    r'wget .*\|\s*sh',
    r'eval\s*\(',
    r'process\.env\[',
]


def _levenshtein(a: str, b: str) -> int:
    # simple iterative DP
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j - 1] + 1
            change = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(add, delete, change))
        prev = cur
    return prev[-1]


def detect_typosquat(name: str, known_names: List[str], threshold: int = 2) -> Tuple[bool, str]:
    name_l = name.lower()
    best = None
    best_score = 9999
    for k in known_names:
        d = _levenshtein(name_l, k.lower())
        if d < best_score:
            best_score = d
            best = k
    return (best_score <= threshold, best if best_score <= threshold else '')


def analyze_npm_package(package_json: Dict[str, Any], known_registry: List[str] = None) -> Dict[str, Any]:
    """Analyze npm package.json-like metadata and return normalized summary with factors."""
    out_factors: List[Dict[str, Any]] = []
    name = package_json.get('name', '')
    version = package_json.get('version', '')
    deps = {**(package_json.get('dependencies') or {}), **(package_json.get('devDependencies') or {})}
    scripts = package_json.get('scripts', {}) or {}
    suspicious_scripts: List[Dict[str, Any]] = []
    for k, v in scripts.items():
        sv = str(v)
        risky = False
        for pat in SUSPICIOUS_INSTALL_PATTERNS:
            if re.search(pat, sv, re.IGNORECASE):
                risky = True
                break
        if any(x in sv.lower() for x in ['powershell', 'cmd.exe', 'nc ', 'netcat', 'bash -c', 'Invoke-WebRequest']):
            risky = True
        if risky:
            suspicious_scripts.append({'script': k, 'cmd': v})
    if suspicious_scripts:
        out_factors.append({'factor': 'supply_chain:suspicious_scripts', 'score': 0.6, 'producer': 'package_integrity', 'count': len(suspicious_scripts)})
    # typosquat detection
    if known_registry:
        ts, victim = detect_typosquat(name, known_registry)
        if ts:
            out_factors.append({'factor': 'supply_chain:typosquat', 'score': 0.5, 'producer': 'package_integrity', 'target': victim})
    # suspicious fields
    if package_json.get('bin') and package_json.get('author') in (None, ''):
        out_factors.append({'factor': 'supply_chain:bin_with_no_author', 'score': 0.25, 'producer': 'package_integrity'})
    # checksum/integrity validation (best-effort)
    integrity = (package_json.get('_integrity') or (package_json.get('dist') or {}).get('integrity'))
    checksum_ok = None
    if isinstance(integrity, str):
        checksum_ok = integrity.startswith('sha512-') or integrity.startswith('sha256-')
        if checksum_ok is False:
            out_factors.append({'factor': 'supply_chain:checksum_invalid', 'score': 0.7, 'producer': 'package_integrity'})
    return FactorResult({
        'producer': 'package_integrity',
        'name': name,
        'version': version,
        'dependencies': deps,
        'scripts_suspicious': suspicious_scripts,
        'integrity': integrity,
        'checksum_ok': checksum_ok,
        'factors': out_factors,
    })


def analyze_pypi_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze PyPI metadata JSON and return normalized summary with factors."""
    out_factors: List[Dict[str, Any]] = []
    name = metadata.get('name') or (metadata.get('info') or {}).get('name') or ''
    version = metadata.get('version') or (metadata.get('info') or {}).get('version') or ''
    requires = metadata.get('requires_dist') or (metadata.get('info') or {}).get('requires_dist') or []
    setup = metadata.get('setup_py') or metadata.get('setup') or ''
    suspicious_hooks: List[Dict[str, Any]] = []
    if setup:
        risky = False
        for pat in SUSPICIOUS_INSTALL_PATTERNS:
            if re.search(pat, setup, re.IGNORECASE):
                risky = True
                break
        if re.search(r'subprocess\.Popen|os\.system|exec\(', setup, re.IGNORECASE):
            risky = True
        if risky:
            suspicious_hooks.append({'hook': 'setup', 'detail': str(setup)[:240]})
            out_factors.append({'factor': 'supply_chain:suspicious_setup_hooks', 'score': 0.6, 'producer': 'package_integrity'})
            out_factors.append({'factor': 'supply_chain:exec_in_setup', 'score': 0.6, 'producer': 'package_integrity'})
            out_factors.append({'factor': 'supply_chain:script_abuse', 'score': 0.5, 'producer': 'package_integrity'})
    # checksum validation via urls[].digests.sha256
    urls = metadata.get('urls') or []
    digests = {}
    for u in urls:
        d = u.get('digests') or {}
        if d:
            digests.update(d)
    checksum_ok = None
    if 'sha256' in digests:
        checksum_ok = bool(digests.get('sha256'))
        if checksum_ok is False:
            out_factors.append({'factor': 'supply_chain:checksum_invalid', 'score': 0.7, 'producer': 'package_integrity'})
    return FactorResult({
        'producer': 'package_integrity',
        'name': name,
        'version': version,
        'requires_dist': requires,
        'suspicious_hooks': suspicious_hooks,
        'digests': digests,
        'checksum_ok': checksum_ok,
        'factors': out_factors,
    })


__all__ = ['analyze_npm_package', 'analyze_pypi_metadata', 'detect_typosquat']
