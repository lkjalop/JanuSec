"""
Simple taxonomy mapper: map MITRE techniques and entity types to STRIDE/PASTA/DREAD/CVSS and compliance controls.
This is intentionally rule-based and lightweight — extend rules or replace with data-driven mapping later.
"""
from typing import Dict, Any, List
import os, json

# Try to load data-driven mappings from data/taxonomy_mappings.json
_MAPPINGS: Dict[str, Any] = {}
_MAPPINGS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'taxonomy_mappings.json')
try:
    if os.path.exists(_MAPPINGS_PATH):
        with open(_MAPPINGS_PATH, 'r', encoding='utf-8') as fh:
            _MAPPINGS = json.load(fh)
except Exception:
    _MAPPINGS = {}


def map_mitre_to_taxonomies(mitre_ids: List[str]) -> Dict[str, Any]:
    stride = set()
    dread_scores = []
    cvss_scores = []
    controls = set()
    # First, use data-driven mappings if present
    mitre_map = _MAPPINGS.get('mitre', {}) if isinstance(_MAPPINGS, dict) else {}
    for m in (mitre_ids or []):
        entry = mitre_map.get(m, {})
        for s in entry.get('stride', []) or []:
            stride.add(s)
        if 'dread' in entry:
            try:
                dread_scores.append(float(entry.get('dread') or 0))
            except Exception:
                pass
        if 'cvss' in entry:
            try:
                cvss_scores.append(float(entry.get('cvss') or 0))
            except Exception:
                pass
        for c in entry.get('controls', []) or []:
            controls.add(c)

    avg_dread = sum(dread_scores)/len(dread_scores) if dread_scores else 0.0
    avg_cvss = sum(cvss_scores)/len(cvss_scores) if cvss_scores else 0.0
    return {
        'stride': list(sorted(stride)),
        'dread_score': round(avg_dread,2),
        'cvss_base': round(avg_cvss,1),
        'compliance_controls': list(sorted(controls))
    }


def enrich_graph_with_taxonomies(graph: Dict[str, Any], extras: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Add taxonomy mapping to graph-level and node-level summaries.
    - If extras contains 'mitre_techniques' list, map them; else try to pull techniques from nodes' metadata.
    """
    mitre_ids = []
    if extras and isinstance(extras.get('mitre_techniques'), list):
        mitre_ids = extras.get('mitre_techniques')
    # fallback: scan nodes for 'mitre' field
    if not mitre_ids:
        for n in graph.get('nodes', []) or []:
            try:
                mt = n.get('mitre') or n.get('mitre_techniques')
                if isinstance(mt, list):
                    mitre_ids.extend(mt)
            except Exception:
                pass
    mapped = map_mitre_to_taxonomies(list(dict.fromkeys(mitre_ids)))
    out = dict(graph)
    out['taxonomies'] = mapped
    # optionally attach factor-level tags if data-driven 'factors' present
    factors = _MAPPINGS.get('factors', []) if isinstance(_MAPPINGS, dict) else []
    if factors:
        out['factors_catalog'] = factors
    return out
