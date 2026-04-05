"""Factor aliasing and normalization helpers.

Provide a mapping from legacy factor strings to canonical factor names and
simple helpers to normalize lists of factor strings. This enables gradual
renaming while preserving backward compatibility across the codebase and tests.
"""
from __future__ import annotations
from typing import List, Dict

# Legacy -> canonical map (extend as we discover more legacy names)
LEGACY_TO_CANONICAL: Dict[str, str] = {
    'remote:mfa_missing': 'remote:no_mfa',
    'iam:key_no_mfa': 'remote:no_mfa',
    'email:homograph': 'email:domain_homograph',
    'email:homograph_domain': 'email:domain_homograph',
    'net:beacon_like': 'net:beacon_periodic',
    'beacon_periodic': 'net:beacon_periodic',
}

# Also provide canonical -> aliases for diagnostics
CANONICAL_ALIASES: Dict[str, List[str]] = {}
for old, new in LEGACY_TO_CANONICAL.items():
    CANONICAL_ALIASES.setdefault(new, []).append(old)


def normalize_factor(f: str) -> str:
    if not f:
        return f
    f = str(f)
    # direct map
    if f in LEGACY_TO_CANONICAL:
        return LEGACY_TO_CANONICAL[f]
    return f


def normalize_factors(factors: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for f in factors or []:
        cf = normalize_factor(f)
        if cf not in seen:
            out.append(cf)
            seen.add(cf)
    return out


__all__ = ['LEGACY_TO_CANONICAL','CANONICAL_ALIASES','normalize_factor','normalize_factors']
