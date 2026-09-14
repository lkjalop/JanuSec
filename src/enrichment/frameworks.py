"""Small enrichment helpers for MITRE/DREAD/STRIDE/PASTA scaffolding.

This module provides light-weight, deterministic mappings suitable for demo
enrichment and unit testing. It intentionally avoids external dependencies.
"""
from __future__ import annotations
from typing import List, Dict, Iterable


MITRE_MAP: Dict[str, List[str]] = {
    # factor -> technique ids (small sample)
    'cmd_exec': ['T1059'],
    'ransomware_behavior': ['T1486'],
    'smb_write': ['T1021'],
    'phishing_attachment': ['T1566'],
}


def map_factors_to_mitre(factors: Iterable[str]) -> List[str]:
    out: List[str] = []
    for f in factors:
        # Normalize by chopping any suffix after ':' (e.g., 'T1566.001:detail')
        token = f.split(':')[0]

        # Legacy style: 'mitre_TA0008' -> include 'TA0008' as a tactic ID
        if token.startswith('mitre_'):
            tac = token.split('_', 1)[1]
            if tac and tac not in out:
                out.append(tac)
            continue

        # Direct MITRE technique ID (e.g., 'T1566' or 'T1566.001'): include as-is
        if token.startswith('T') or token.startswith('TA'):
            if token not in out:
                out.append(token)
            continue

        # Factor-to-technique mapping (fallback)
        key = token
        if key in MITRE_MAP:
            for t in MITRE_MAP[key]:
                if t not in out:
                    out.append(t)
    return out


def map_stride(factors: Iterable[str]) -> List[str]:
    # simple heuristics mapping factors to STRIDE categories
    out = set()
    for f in factors:
        if 'spoof' in f or 'ip-spoof' in f:
            out.add('spoofing')
        if 'tamper' in f or 'file:modified' in f:
            out.add('tampering')
        if 'repud' in f:
            out.add('repudiation')
        if 'exfil' in f or 'data_exfil' in f:
            out.add('information_disclosure')
        if 'denial' in f or 'dos' in f:
            out.add('denial')
        if 'privilege' in f or 'elevate' in f:
            out.add('elevation')
        if 'discovery' in f or 'recon' in f:
            out.add('discovery')
    return list(out)


def calculate_dread(event: dict, factors: Iterable[str]) -> Dict[str, float]:
    # Minimal deterministic DREAD scoring using factor presence; values 0-10
    base = 0
    for f in factors:
        if 'ransom' in f or 'ransomware' in f or 'encrypt' in f:
            base += 7
        if 'cmd_exec' in f or 'suspicious_cmd' in f:
            base += 3
        if 'exfil' in f:
            base += 4

    # Normalize to 0-10
    def clamp(x):
        return max(0.0, min(10.0, float(x)))

    damage = clamp(base * 1.0)
    reproducibility = clamp(base * 0.6)
    exploitability = clamp(base * 0.5)
    affected = clamp(2.0 if 'network' in (event.get('category') or '') else 1.0)
    discoverability = clamp(3.0 if 'public' in (event.get('source') or '') else 1.0)

    return {
        'damage': damage,
        'reproducibility': reproducibility,
        'exploitability': exploitability,
        'affected': affected,
        'discoverability': discoverability,
        'average': round((damage + reproducibility + exploitability + affected + discoverability) / 5.0, 2)
    }


def attach_pasta_scenarios(event: dict) -> List[dict]:
    # Simple PASTA placeholder - return empty unless event matches high-risk marker
    factors = event.get('factors') or []
    out = []
    for f in factors:
        if 'ransomware' in f or 'ransom' in f:
            out.append({'id': 'pasta-ransom-1', 'status': 'observed', 'composite_risk': 4.5})
    return out


__all__ = ['map_factors_to_mitre', 'map_stride', 'calculate_dread', 'attach_pasta_scenarios']