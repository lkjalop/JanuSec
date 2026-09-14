from typing import Dict, Any

def compute_mapping_semantics(factors: list, mapping_stats: Dict[str, Any], canonical_fields: list) -> float:
    """Compute a normalized mapping semantics score from detected factors and mapping stats.

    Returns a float in [0.0, 1.0].
    """
    try:
        # Base from explicitly generated mapping_semantics_* factors
        score = 0.0
        for f in factors or []:
            if isinstance(f, dict):
                name = f.get('factor') or f.get('name') or ''
                if str(name).startswith('mapping_semantics'):
                    try:
                        score += float(f.get('score') or 0.0)
                    except Exception:
                        pass
        # Bonus from mapping_stats coverage of high-value fields
        hv = ['user','host','process','file_hash','domain']
        hv_present = sum(1 for h in hv if mapping_stats.get(h))
        score += min(0.5, hv_present / max(1, len(hv)) * 0.5)
        # Normalize to 0..1
        return max(0.0, min(1.0, float(score)))
    except Exception:
        return 0.0
