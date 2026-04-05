"""Security factor mapping scaffolding for explainable AI overlays."""
from __future__ import annotations
from typing import List, Dict

MITRE_MAP: Dict[str, List[str]] = {
    'endpoint:obfuscation_b64': ['T1027'],
    'endpoint:lolbin_cmd_tfidf_rare': ['T1218'],
    'net:beacon_periodic': ['T1071'],
    'baseline:known_bad_ip': ['T1583'],
}

STRIDE_MAP: Dict[str, List[str]] = {
    'baseline:known_bad_ip': ['Repudiation','Tampering'],
    'net:beacon_periodic': ['Information Disclosure'],
}

DREAD_WEIGHTS: Dict[str, Dict[str, float]] = {
    'baseline:known_bad_ip': {'D':0.6,'R':0.4,'E':0.5,'A':0.5,'Dsc':0.3},
    'net:beacon_periodic': {'D':0.4,'R':0.5,'E':0.6,'A':0.3,'Dsc':0.5},
}

PASTA_STAGES: Dict[str, List[str]] = {
    'net:beacon_periodic': ['Stage 5 Attack Modeling','Stage 6 Risk Analysis'],
}

def enrich_factors(factors: List[str]) -> Dict[str, Dict[str, List[str]]]:
    enriched: Dict[str, Dict[str, List[str]]] = {}
    for f in factors:
        enriched[f] = {
            'mitre': MITRE_MAP.get(f, []),
            'stride': STRIDE_MAP.get(f, []),
            'pasta': PASTA_STAGES.get(f, []),
        }
        if f in DREAD_WEIGHTS:
            enriched[f]['dread'] = DREAD_WEIGHTS[f]  # type: ignore
    return enriched

__all__ = ['enrich_factors','MITRE_MAP','STRIDE_MAP','DREAD_WEIGHTS','PASTA_STAGES']
