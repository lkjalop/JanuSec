"""Mapping layer: enrichment -> CVSS bucket -> DREAD inputs.

Lightweight, heuristic mapping used by CRQ/FAIR-shadow to convert enrichment
signals into numeric inputs suitable for DREAD or other scoring models.
"""
from __future__ import annotations
from typing import Dict, Any

def epss_to_cvss_bucket(epss_score: float) -> str:
    """Map EPSS score [0..1] to a CVSS-like bucket: low/medium/high/critical."""
    if epss_score >= 0.9:
        return 'critical'
    if epss_score >= 0.65:
        return 'high'
    if epss_score >= 0.3:
        return 'medium'
    return 'low'


def cvss_bucket_to_dread(bucket: str) -> Dict[str, int]:
    """Heuristic mapping from CVSS bucket to DREAD numeric inputs (0..10).

    Returns a dict with keys: damage, reproducibility, exploitability, affected_users, discoverability
    """
    if bucket == 'critical':
        return {'damage':9,'repro':8,'exploit':9,'affected':8,'discover':8}
    if bucket == 'high':
        return {'damage':7,'repro':6,'exploit':7,'affected':6,'discover':6}
    if bucket == 'medium':
        return {'damage':5,'repro':4,'exploit':4,'affected':4,'discover':4}
    return {'damage':2,'repro':2,'exploit':2,'affected':1,'discover':1}


def enrichment_to_dread_inputs(enrich: Dict[str, Any]) -> Dict[str, int]:
    """Convert a cached enrichment record into DREAD inputs.

    Example: enrich could be {'epss_score':0.7, 'source':'epss'} or KEV candidate info.
    """
    if not enrich:
        return cvss_bucket_to_dread('low')
    if 'epss_score' in enrich:
        bucket = epss_to_cvss_bucket(float(enrich.get('epss_score') or 0.0))
        return cvss_bucket_to_dread(bucket)
    if 'kev_candidate' in enrich:
        if enrich.get('kev_candidate'):
            # KEV candidate => escalate
            return cvss_bucket_to_dread('high')
    return cvss_bucket_to_dread('low')
