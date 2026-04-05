"""SBOM and vulnerability enrichment helpers.

Provides a small interface to lookup image/component vulnerabilities and mark KEV candidates.
This is intentionally pluggable so CI or operators can wire real feeds.
"""
from __future__ import annotations

import json
from typing import Dict, List, Any


def lookup_image_vulns(image: str) -> List[Dict[str, Any]]:
    """Lookup vulnerabilities for an image. Default: check app.state SBOM store if present.

    Returns a list of vuln dicts: {cve, score, kev_candidate}
    """
    try:
        # Try to use a lightweight in-repo SBOM mapping stored under `data/sbom_store.json`
        with open('data/sbom_store.json', 'r', encoding='utf-8') as fh:
            store = json.load(fh)
        recs = store.get(image) or []
        return recs
    except Exception:
        # fallback: empty
        return []


def mark_kev_candidates(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Annotate vulns with `kev_candidate` boolean when score >= threshold or known list.

    This is a simple heuristic suitable for demo/testing.
    """
    out = []
    for v in vulns:
        try:
            score = float(v.get('score') or 0.0)
        except Exception:
            score = 0.0
        v = dict(v)
        v['kev_candidate'] = (score >= 7.0) or bool(v.get('kev_flag'))
        out.append(v)
    return out
