"""HopGraph reconstruction helpers: normalization, scoring, explainable factors,
adaptive EWMA alpha, and session persistence utilities.

This module provides lightweight, testable helpers to be used by the core
HopGraph engine and session builder endpoints.
"""
from __future__ import annotations

import os
import json
import time
import math
from typing import Any, Dict, List, Tuple, Optional
from collections import defaultdict

SESSION_PERSIST_DIR = os.getenv('SESSION_PERSIST_DIR', 'data/sessions')
EWMA_HISTORY_PATH = os.getenv('EWMA_HISTORY_PATH', os.path.join(SESSION_PERSIST_DIR, 'ewma_history.json'))
os.makedirs(SESSION_PERSIST_DIR, exist_ok=True)


def _session_persist_dir() -> str:
    path = os.getenv('SESSION_PERSIST_DIR', SESSION_PERSIST_DIR)
    os.makedirs(path, exist_ok=True)
    return path


def normalize_field(field: str, value: Any) -> Any:
    if value is None:
        return value
    if field in {'domain', 'email', 'user', 'host', 'process'}:
        try:
            return str(value).strip().lower()
        except Exception:
            return value
    if field in {'ip', 'ip_src', 'ip_dst'}:
        # naive IP normalization: strip whitespace
        return str(value).strip()
    if field == 'file_hash':
        # normalize hex digest to lowercase and trim
        return str(value).strip().lower()
    return value


def normalize_event(event: Dict[str, Any], mapping: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    out = {}
    for k, v in event.items():
        canon = k
        if mapping and k in mapping:
            canon = mapping[k]
        out[canon] = normalize_field(canon, v)
    # attach provenance
    prov = out.setdefault('_prov', {})
    prov.setdefault('source', event.get('source'))
    prov.setdefault('ts', event.get('ts', time.time()))
    prov.setdefault('event_id', event.get('event_id'))
    prov.setdefault('dataset_id', event.get('dataset_id'))
    return out


def path_factors(path: List[Dict[str, Any]]) -> Dict[str, Tuple[float, str]]:
    """Compute explainable factors for a path (list of node dicts).
    Returns a map factor_name -> (contribution, message).
    """
    factors: Dict[str, Tuple[float, str]] = {}
    # High-entropy: compute Shannon entropy across candidate artifacts
    try:
        from utils.entropy import max_entropy  # type: ignore
    except Exception:
        try:
            from src.utils.entropy import max_entropy  # type: ignore
        except Exception:
            max_entropy = None  # type: ignore
    entropy_sources = []
    for n in path:
        for f in ('file_hash','process','domain'):
            v = n.get(f)
            if isinstance(v,str) and v:
                entropy_sources.append(v)
    ent = 0.0
    if max_entropy:
        ent = max_entropy(entropy_sources)
    entropy_threshold = 3.5
    try:
        entropy_threshold = float(os.getenv('ENTROPY_HIGH_THRESHOLD', entropy_threshold))
    except Exception:
        pass
    has_file_hash = any(n.get('file_hash') for n in path)
    if has_file_hash or ent >= entropy_threshold:
        # scale contribution with entropy (cap 0.30)
        base = 0.18 if has_file_hash else 0.12
        bonus = min(0.12, (max(0.0, ent - (entropy_threshold-0.5)) / (entropy_threshold)) * 0.12)
        factors['high_entropy'] = (round(min(0.30, base + bonus),4), f'high entropy artifact ent={ent:.2f} threshold={entropy_threshold:.2f} file_hash={"yes" if has_file_hash else "no"}')

    # Signature match: registry patterns or explicit flag
    sig_hits = []
    try:
        from src.signatures.registry import match_signatures  # type: ignore
    except Exception:
        try:
            from signatures.registry import match_signatures  # type: ignore
        except Exception:
            match_signatures = None  # type: ignore
    for n in path:
        if n.get('signature_match'):
            sig_hits.append('explicit')
        if match_signatures:
            for h in match_signatures(n):
                sig_hits.append(h)
    if sig_hits:
        # scale with distinct hits (cap 0.35)
        distinct = len(set(sig_hits))
        contrib = min(0.35, 0.18 + (distinct-1)*0.05)
        factors['signature_match'] = (round(contrib,4), f'signature hits: {",".join(sig_hits)}')

    # NXDOMAIN spike: derive from baseline service if available
    try:  # dynamic import to avoid hard dependency in tests without baseline
        try:
            from baseline.services import get_nxdomain_baseline  # type: ignore
        except Exception:
            from src.baseline.services import get_nxdomain_baseline  # type: ignore
        nx = get_nxdomain_baseline()
        rate = nx.get('rate', 0.0)
        threshold = nx.get('threshold', 0.35)
        # Threshold heuristic from baseline currently sets threshold = max(0.35, rate+0.15)
        # which makes rate >= threshold rarely true. Use static floor 0.35 for trigger.
        if rate >= 0.35:
            overshoot = min(0.5, max(0.0, rate - 0.35))
            base = 0.10
            bonus = (overshoot / 0.5) * 0.05
            factors['nxdomain_spike'] = (round(base + bonus, 4), f'nxdomain rate {rate:.2f} >= 0.35 (baseline threshold {threshold:.2f})')
    except Exception:
        # fallback to static heuristic from any annotated node
        for n in path:
            nr = n.get('nxdomain_rate')
            if nr is not None and nr >= 0.35:
                factors['nxdomain_spike'] = (0.15, f'nxdomain rate {nr:.2f} >= threshold')
                break

    # ASN rarity: use baseline rarity scores if available else node-provided field
    asn_values = []
    for n in path:
        for key in ('asn','asn_src','asn_dst'):
            if n.get(key):
                asn_values.append(str(n.get(key)))
    rarity_lookup = {}
    try:
        try:
            from baseline.services import get_asn_rarity  # type: ignore
        except Exception:
            from src.baseline.services import get_asn_rarity  # type: ignore
        rarity_data = get_asn_rarity()
        rarity_lookup = rarity_data.get('rarity_scores', {}) or {}
    except Exception:
        pass
    asn_score_component = 0.0
    contributing = []
    for asn in asn_values:
        r = rarity_lookup.get(asn)
        if r is None:
            continue
        asn_score_component = max(asn_score_component, float(r))
        contributing.append(f"{asn}:{r}")
    if asn_score_component > 0:
        # scale up to 0.2
        score = min(0.2, 0.2 * asn_score_component)
        factors['asn_rarity'] = (round(score,4), 'rare ASN ' + ','.join(contributing))
    else:
        # fallback to existing node-supplied rarity numeric field if present
        for n in path:
            ar = n.get('asn_rarity')
            if ar is not None:
                score = min(0.2, max(0.0, 0.2 * float(ar)))
                factors['asn_rarity'] = (round(score,4), f'ASN rarity factor {ar}')
                break

    # Domain diversity: count distinct domain prefixes
    domains = {n.get('domain') for n in path if n.get('domain')}
    if domains:
        dd = len(domains)
        contrib = min(0.15, 0.03 * dd)
        factors['domain_diversity'] = (contrib, f'{dd} distinct domains in path')

    # Mapping semantics: bonus for presence of high-value fields
    hv = 0
    for n in path:
        for f in ('user', 'host', 'process', 'file_hash', 'domain'):
            if n.get(f):
                hv += 1
    if hv >= 3:
        factors['mapping_semantics'] = (0.07, f'{hv} high-value fields present')
    if hv >= 4:
        factors['mapping_semantics'] = (0.15, f'{hv} high-value fields present')

    return factors


def score_path(path: List[Dict[str, Any]], weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    factors = path_factors(path)
    if weights is None:
        weights = {
            'high_entropy': 1.0,
            'signature_match': 1.0,
            'nxdomain_spike': 1.0,
            'asn_rarity': 1.0,
            'domain_diversity': 1.0,
            'mapping_semantics': 1.0,
        }
    total = 0.0
    contributions = {}
    for k, (v, msg) in factors.items():
        w = weights.get(k, 1.0)
        contrib = v * w
        contributions[k] = {'contribution': contrib, 'message': msg}
        total += contrib

    # clamp score to 0..1
    score = max(0.0, min(1.0, total))
    return {'score': score, 'contributions': contributions}


def adaptive_ewma_alpha(counts: List[float], base_alpha: float = 0.6, min_alpha: float = 0.3, max_alpha: float = 0.85, vol_scale: float = 0.4) -> float:
    """Derive an EWMA alpha from volatility (stddev/mean) of non-zero counts."""
    vals = [v for v in counts if v is not None and v > 0]
    if not vals:
        return base_alpha
    mean = sum(vals) / len(vals)
    var = sum((x - mean) ** 2 for x in vals) / len(vals)
    std = math.sqrt(var)
    vol = std / mean if mean > 0 else 0.0
    # higher volatility -> lower alpha (more smoothing)
    alpha = base_alpha - (vol * vol_scale)
    alpha = max(min_alpha, min(max_alpha, alpha))
    return alpha


def persist_session(session_id: str, payload: Dict[str, Any]) -> None:
    path = os.path.join(_session_persist_dir(), f"{session_id}.json")
    payload['persisted_at'] = time.time()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f)


def load_session(session_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(_session_persist_dir(), f"{session_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def cleanup_sessions(ttl_seconds: int = 3600):
    now = time.time()
    for fname in os.listdir(_session_persist_dir()):
        if not fname.endswith('.json'):
            continue
        path = os.path.join(_session_persist_dir(), fname)
        try:
            m = os.path.getmtime(path)
            if (now - m) > ttl_seconds:
                os.remove(path)
        except Exception:
            pass
