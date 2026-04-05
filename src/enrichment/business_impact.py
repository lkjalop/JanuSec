"""Business impact lenses mapping.

Maps observed factors and lightweight context to impact categories:
- account_compromise
- code_integrity
- data_exfiltration
- regulatory_exposure

This module is deterministic and avoids external dependencies.
"""
from __future__ import annotations
from typing import Dict, List, Iterable, Any


IMPACT_CATEGORIES = [
    'account_compromise',
    'code_integrity',
    'data_exfiltration',
    'regulatory_exposure',
]


def _norm(s: Any) -> str:
    try:
        return str(s or '').lower()
    except Exception:
        return ''


def map_business_impacts(factors: Iterable[str]) -> Dict[str, bool]:
    """Return a boolean map for impact categories based on factor tokens.

    Heuristics:
    - account_compromise: privilege escalation, oauth, credential, login/profile, key creation
    - code_integrity: supply chain, package/cicd, provenance, unsigned, signature mismatch
    - data_exfiltration: exfil, beaconing, tunnel, c2, dns exfil
    - regulatory_exposure: gdpr/regulatory tags, KEV presence, high CVSS clusters
    """
    fset = { _norm(f) for f in factors if isinstance(f, str) }
    def any_token(tokens: List[str]) -> bool:
        return any(any(t in f for t in tokens) for f in fset)

    account = any_token(['privilege', 'escalation', 'oauth', 'credential', 'login', 'profile', 'createaccesskey', 'accesskey'])
    code = any_token(['supply_chain', 'package', 'cicd', 'workflow', 'provenance', 'unsigned', 'signature_mismatch'])
    exfil = any_token(['exfil', 'beacon', 'tunnel', 'c2', 'dns_exfil'])
    reg = any_token(['gdpr', 'regulatory', 'kev', 'cvss_critical', 'epss'])

    return {
        'account_compromise': bool(account),
        'code_integrity': bool(code),
        'data_exfiltration': bool(exfil),
        'regulatory_exposure': bool(reg),
    }


def summarize_business_impact(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate business impact across decision/record entries.

    Each record may contain `factors` list. Returns counts per impact and a top list.
    """
    counts = {k: 0 for k in IMPACT_CATEGORIES}
    examples: Dict[str, List[str]] = {k: [] for k in IMPACT_CATEGORIES}
    for rec in records:
        facs = [f for f in (rec.get('factors') or []) if isinstance(f, str)]
        imap = map_business_impacts(facs)
        for k, v in imap.items():
            if v:
                counts[k] += 1
                # store up to 3 example factors contributing to each impact
                if len(examples[k]) < 3:
                    try:
                        examples[k].extend(facs[:3 - len(examples[k])])
                    except Exception:
                        pass
    top = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return {
        'counts': counts,
        'top_impacts': [{'category': k, 'count': n, 'examples': examples.get(k) or []} for k, n in top],
    }


__all__ = ['IMPACT_CATEGORIES','map_business_impacts','summarize_business_impact']
