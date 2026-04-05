from typing import Dict, Any, List


def _top_n(items: List[Any], n: int = 5) -> List[Any]:
    return items[:n] if items else []


def top5_risk_drivers(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return top 5 risk drivers from report.risk_quantification and factors.
    Expects keys like 'verdict' with 'top_contributing_factors' and 'risk_quantification'.
    """
    drivers: List[Dict[str, Any]] = []
    rq = report.get("risk_quantification", {})
    for k in [
        "damage_potential",
        "reproducibility",
        "exploitability",
        "affected_users",
        "discoverability",
    ]:
        if k in rq:
            drivers.append({"driver": k, "value": rq[k]})
    # Blend top factors by contribution_score
    factors = report.get("verdict", {}).get("top_contributing_factors", [])
    sorted_factors = sorted(
        factors,
        key=lambda f: f.get("contribution_score", 0.0) if isinstance(f, dict) else 0.0,
        reverse=True,
    )
    for f in sorted_factors:
        if isinstance(f, dict):
            drivers.append(
                {
                    "driver": f.get("factor_name", "factor"),
                    "value": f.get("contribution_score", 0.0),
                    "category": f.get("factor_category"),
                }
            )
        else:
            drivers.append({"driver": str(f), "value": 0.0, "category": None})
    return _top_n(drivers, 5)


def top5_factors(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    factors = report.get("verdict", {}).get("all_factors", [])
    sorted_factors = sorted(
        factors,
        key=lambda f: f.get("contribution_score", 0.0) if isinstance(f, dict) else 0.0,
        reverse=True,
    )
    result = []
    for f in sorted_factors:
        if isinstance(f, dict):
            result.append({
                "name": f.get("factor_name"),
                "score": f.get("contribution_score", 0.0),
                "evidence_count": f.get("evidence_count", 0),
                "category": f.get("factor_category"),
            })
        else:
            result.append({"name": str(f), "score": 0.0, "evidence_count": 0, "category": None})
    return _top_n(result, 5)


def top5_iocs(report: Dict[str, Any]) -> Dict[str, List[str]]:
    """Aggregate IOCs from evidence items and return top 5 per type."""
    evidence = report.get("evidence_items", [])
    out: Dict[str, List[str]] = {"ip": [], "domain": [], "hash": [], "email": []}
    seen: Dict[str, set] = {k: set() for k in out.keys()}
    for ev in evidence:
        iocs = ev.get("extracted_iocs", {})
        for t, vals in iocs.items():
            if t in out:
                for v in vals:
                    if v not in seen[t]:
                        seen[t].add(v)
                        out[t].append(v)
    return {k: _top_n(v, 5) for k, v in out.items()}


def top5_impacted_entities(report: Dict[str, Any]) -> List[str]:
    timeline = report.get("attack_timeline", [])
    entities: List[str] = []
    seen = set()
    for evt in timeline:
        entity = evt.get("entity")
        if entity and entity not in seen:
            seen.add(entity)
            entities.append(entity)
    return _top_n(entities, 5)


def top5_recommended_actions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = report.get("recommended_actions", [])
    # Prefer urgency order: immediate > urgent > normal > low
    urgency_rank = {"immediate": 0, "urgent": 1, "normal": 2, "low": 3}
    sorted_actions = sorted(
        actions,
        key=lambda a: urgency_rank.get(str(a.get("urgency", "low")).lower(), 99),
    )
    return _top_n(
        [
            {
                "action": a.get("primary_action"),
                "urgency": a.get("urgency"),
                "persona": a.get("persona"),
            }
            for a in sorted_actions
        ],
        5,
    )
