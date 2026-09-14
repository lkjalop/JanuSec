"""Feature extraction for ml_score model.
Provides a deterministic transformer that converts a llm_row and assessment
into a numeric feature vector suitable for LightGBM training/inference.
"""
from __future__ import annotations
from typing import Dict, Any, List

def extract_row_features(row: Dict[str, Any], assessment: Dict[str, Any] | None = None) -> Dict[str, float]:
    f: Dict[str, float] = {}
    try:
        v = str((row.get('verdict') or row.get('classification') or '')).upper()
        f['verdict_critical'] = 1.0 if v == 'CRITICAL' else 0.0
        f['verdict_high'] = 1.0 if v == 'HIGH' else 0.0
        f['verdict_suspicious'] = 1.0 if v in {'SUSPICIOUS','FAIL'} else 0.0
    except Exception:
        f['verdict_critical'] = f['verdict_high'] = f['verdict_suspicious'] = 0.0
    # DREAD
    try:
        dd = row.get('_dread') or row.get('dread') or {}
        if isinstance(dd, dict):
            f['dread_score'] = float(dd.get('score') or 0.0)
        else:
            f['dread_score'] = float(dd or 0.0)
    except Exception:
        f['dread_score'] = 0.0
    # factors
    try:
        f['factors_count'] = float(len(row.get('factors') or []))
    except Exception:
        f['factors_count'] = 0.0
    # hopgraph hints
    try:
        gh = row.get('graph_context') or {}
        f['gh_hotspots'] = 1.0 if gh.get('hotspots') else 0.0
        f['gh_mapping_count'] = float(len(gh.get('mapping_stats') or {}))
    except Exception:
        f['gh_hotspots'] = 0.0
        f['gh_mapping_count'] = 0.0
    # recency relative to assessment created
    try:
        ts = None
        for k in ('ts','time','timestamp','created','evt_time'):
            if row.get(k) is not None:
                try:
                    ts = float(row.get(k))
                    break
                except Exception:
                    pass
        if ts and assessment and assessment.get('created'):
            age = max(0.0, float(assessment.get('created') or 0) - ts)
            f['age_seconds'] = float(age)
        else:
            f['age_seconds'] = 0.0
    except Exception:
        f['age_seconds'] = 0.0
    # LLM confidence if available
    try:
        meta = row.get('llm_meta') or {}
        f['llm_confidence'] = float(meta.get('confidence') or 0.0)
    except Exception:
        f['llm_confidence'] = 0.0

    # Normalization helpers: keep values as floats, training script handles scaling
    return f

def extract_feature_matrix(rows: List[Dict[str, Any]], assessment: Dict[str, Any] | None = None) -> List[Dict[str, float]]:
    return [extract_row_features(r, assessment) for r in rows]
