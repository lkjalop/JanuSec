"""Map HopGraph explain_chain outputs to DREAD and STRIDE-like factors.

This module provides a compact mapping heuristic used by unit tests and UI
components to surface threat-model-aware metadata for an explain chain.
"""
from __future__ import annotations
from typing import Dict, Any, List
import os


def map_chain_to_threat_model(chain: Dict[str, Any]) -> Dict[str, Any]:
    """Given an explain_chain result with 'hops', compute simple DREAD and STRIDE scores.

    Returns a dict with keys: 'dread': {Damage,...}, 'stride': {categories...}, 'severity'
    """
    hops = (chain.get('hops') or [])
    # basic heuristics
    damage = 0.0
    exploitability = 0.0
    discoverability = 0.0
    # Use canonical STRIDE naming ('information_disclosure'); retain legacy alias for compatibility
    stride = {'spoofing': False, 'tampering': False, 'repudiation': False, 'information_disclosure': False, 'denial': False, 'elevation': False}
    legacy_alias = 'info_disclosure'

    for h in hops:
        et = (h.get('etype') or '').lower()
        src = (h.get('source') or '').lower()
        contrib = h.get('contrib_score') or 0.0
        # rule-of-thumb mappings
        if 'loads_hash' in et or 'exec' in et or 'runs' in et:
            damage += 1.0 * contrib
            stride['elevation'] = True
        if 'contacts_domain' in et or 'connects_to' in et or 'dns_a' in et:
            stride['information_disclosure'] = True
            discoverability += 0.5 * contrib
        if 'tls_cert' in et or 'tls_ja3' in et:
            exploitability += 0.2 * contrib
        if 'connects_from' in et:
            stride['spoofing'] = True

    # normalize
    def _norm(x):
        return min(1.0, float(x))

    dread = {
        'damage': _norm(damage),
        'reproducibility': 0.5,
        'exploitability': _norm(exploitability),
        'affected_users': 0.5,
        'discoverability': _norm(discoverability)
    }
    # Very simple severity heuristic
    severity = min(1.0, (dread['damage'] + dread['exploitability'] + dread['discoverability']) / 3.0)
    # Optional gray-tier uplift: boost borderline severity slightly when enabled
    try:
        boost = float(os.getenv('GRAY_RECALL_BOOST','0') or 0.0)
    except Exception:
        boost = 0.0
    if boost > 0.0 and 0.45 <= severity <= 0.60:
        severity = min(1.0, round(severity + min(0.2, boost), 3))

    # Add legacy alias key if not present to avoid breaking older consumers
    if legacy_alias not in stride:
        stride[legacy_alias] = stride['information_disclosure']
    return {'dread': dread, 'stride': stride, 'severity': severity}


def map_factors_to_tags(factors: List[str]) -> Dict[str, Any]:
    """Return combined mapping/correlation tags across frameworks for given factors.

    Always returns at least keys: mitre, atlas, owasp_llm. When available, also
    includes: stride, dread, maestro, pasta, cvss, epss, hopgraph.
    """
    base = {'mitre': [], 'atlas': [], 'owasp_llm': []}
    # Start with static factor->tag mappings
    try:
        from src.core.mappings.factor_to_mitre import get_all_mappings  # type: ignore
        result = get_all_mappings(list(factors or []))
        base['mitre'] = list(result.get('mitre') or [])
        base['atlas'] = list(result.get('atlas') or [])
        base['owasp_llm'] = list(result.get('owasp_llm') or [])
    except Exception:
        pass
    # Enrich with unified taxonomy (best-effort)
    try:
        from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore
        model = aggregate_threat_model(list(factors or [])) or {}
        # STRIDE categories
        stride = (model.get('stride') or {}).get('categories') or []
        base['stride'] = [str(s).lower().replace(' ', '_') for s in stride]
        # DREAD components (dict)
        base['dread'] = model.get('dread') or {}
        # MAESTRO phases
        base['maestro'] = list(model.get('maestro') or [])
        # PASTA stages
        base['pasta'] = list(model.get('pasta_stage') or model.get('pasta_stages') or [])
        # CVSS hints (dict)
        base['cvss'] = model.get('cvss') or {}
        # EPSS placeholder (populated elsewhere when CVEs present)
        base['epss'] = []
        # HopGraph domain from factor prefixes
        try:
            base['hopgraph'] = sorted({f.split(':',1)[0] for f in factors if isinstance(f, str) and ':' in f})
        except Exception:
            base['hopgraph'] = []
    except Exception:
        # Keep base keys minimal if taxonomy is unavailable
        pass
    return base
