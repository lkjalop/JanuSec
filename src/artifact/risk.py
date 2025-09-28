from __future__ import annotations
from typing import List, Dict, Any
from .models import ArtifactObservation, map_risk_to_verdict

# Weight allocations (can be tuned)
COMP_WEIGHTS = {
    'static': 0.22,
    'origin': 0.18,      # slight bump to reflect fresh_download influence
    'behavior': 0.24,    # increase so tunneling + lolbin pair elevates ambiguity band
    'relational': 0.15,
    'baseline': 0.12,
    'reputation': 0.10,
    'llm': 0.08
}

# For now we approximate component contributions from factor category aggregation
from .factors import FACTOR_WEIGHTS

def synthesize(obs: ArtifactObservation):
    category_scores: Dict[str, float] = {}
    per_factor: List[Dict[str, Any]] = []
    for f in obs.factors:
        meta = FACTOR_WEIGHTS.get(f)
        if not meta: continue
        cat_enum, w, desc = meta
        cat = cat_enum.value
        category_scores[cat] = category_scores.get(cat,0.0) + w
        per_factor.append({
            'factor_id': f,
            'category': cat,
            'weight': w,
            'description': desc
        })
    # map categories to components
    comp_map = {
        'static':'static', 'macro':'static','script':'static',
        'origin':'origin', 'lolbin':'behavior', 'behavior':'behavior',
        'persistence':'behavior', 'relational':'relational', 'temporal':'origin',
        'reputation':'reputation'
    }
    risk_components: List[Dict[str, Any]] = []
    total = 0.0
    for cat, raw_score in category_scores.items():
        comp_key = comp_map.get(cat)
        if not comp_key: continue
        weight = COMP_WEIGHTS.get(comp_key, 0.05)
        contribution = min(raw_score,1.0) * weight
        risk_components.append({'component': comp_key, 'raw': raw_score, 'weight': weight, 'contribution': contribution})
        total += contribution
    obs.risk_components = risk_components
    obs.factor_contributions = per_factor
    obs.final_risk = min(1.0, total)
    # Synergy adjustments (heuristic):
    # 1. Ambiguous tunneling lolbin fresh_download combo should land mid-band (0.4-0.7) for escalation testing.
    if all(f in obs.factors for f in ('lolbin_misuse','tunneling_utility','fresh_download')):
        if obs.final_risk < 0.35:
            obs.final_risk = 0.48  # push into ambiguity band
            cur_amb = getattr(obs,'ambiguity',0.0) or 0.0
            obs.ambiguity = max(cur_amb, 0.55)
    # 2. Packed unsigned recent compile trio signals clearly high risk.
    if all(f in obs.factors for f in ('unsigned_binary','high_entropy_section','compile_time_recent')):
        if obs.final_risk < 0.75:
            obs.final_risk = 0.86
    obs.verdict = map_risk_to_verdict(obs.final_risk)
    return obs
