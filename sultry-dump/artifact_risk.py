# Copied from JanuSec src/artifact/risk.py (simplified)
from __future__ import annotations
from typing import Any
from artifact_models import ArtifactObservation, map_risk_to_verdict
from artifact_factors import FACTOR_WEIGHTS

COMP_WEIGHTS = {
    'static': 0.22,
    'origin': 0.18,
    'behavior': 0.24,
    'relational': 0.15,
    'baseline': 0.12,
    'reputation': 0.10,
    'llm': 0.08
}

COMP_MAP = {
    'static':'static','macro':'static','script':'static','origin':'origin','lolbin':'behavior',
    'behavior':'behavior','persistence':'behavior','relational':'relational','temporal':'origin','reputation':'reputation'
}

def synthesize(obs: ArtifactObservation):
    category_scores: dict[str,float] = {}
    per_factor: list[dict[str,Any]] = []
    for f in obs.factors:
        meta = FACTOR_WEIGHTS.get(f)
        if not meta: continue
        cat_enum, w, desc = meta
        cat = cat_enum.value
        category_scores[cat] = category_scores.get(cat,0.0) + w
        per_factor.append({'factor_id': f,'category': cat,'weight': w,'description': desc})
    risk_components = []
    total = 0.0
    for cat, raw in category_scores.items():
        ck = COMP_MAP.get(cat)
        if not ck: continue
        weight = COMP_WEIGHTS.get(ck,0.05)
        contrib = min(raw,1.0) * weight
        risk_components.append({'component': ck,'raw': raw,'weight': weight,'contribution': contrib})
        total += contrib
    obs.risk_components = risk_components
    obs.factor_contributions = per_factor
    obs.final_risk = min(1.0, total)
    # Heuristic synergy examples (replace later with learned adjustment layer)
    if all(f in obs.factors for f in ('lolbin_misuse','tunneling_utility','fresh_download')) and obs.final_risk < 0.35:
        obs.final_risk = 0.48; obs.ambiguity = max(getattr(obs,'ambiguity',0.0), 0.55)
    if all(f in obs.factors for f in ('unsigned_binary','high_entropy_section','compile_time_recent')) and obs.final_risk < 0.75:
        obs.final_risk = 0.86
    obs.verdict = map_risk_to_verdict(obs.final_risk)
    return obs
