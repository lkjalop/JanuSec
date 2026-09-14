"""MITRE ATT&CK Navigator layer export (G3).

A pure transform of the techniques already detected in an assessment (from each
finding's deterministic MITRE set) into an ATT&CK Navigator layer JSON — importable at
mitre-attack.github.io/attack-navigator as a per-assessment coverage heatmap. Adds NO
new per-phase mapping tables: it reads the MITRE that the findings already carry, so it
cannot drift from the detection layer.
"""
from __future__ import annotations

from typing import Any

# DREAD-level -> Navigator technique colour (white-to-red severity gradient).
_LEVEL_COLOUR = {
    "critical": "#b30000", "high": "#e34a33", "medium": "#fc8d59",
    "low": "#fdcc8a", "trace": "#fef0d9",
}


def _dread_level(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "trace"


def build_navigator_layer(audit_pack: dict, *, name: str = "JanuSec assessment",
                          description: str = "") -> dict[str, Any]:
    """Build an ATT&CK Navigator (layer format 4.5) JSON from the audit pack's findings."""
    tech: dict[str, dict] = {}
    for f in audit_pack.get("findings", []):
        dread = float((f.get("dread") or {}).get("overall_score") or 0.0)
        actor = f.get("actor") or "unknown"
        for t in f.get("mitre", []):
            tid = str(t).upper()
            rec = tech.setdefault(tid, {"count": 0, "dread": 0.0, "actors": set()})
            rec["count"] += 1
            rec["dread"] = max(rec["dread"], dread)
            rec["actors"].add(actor)

    techniques = []
    for tid, rec in sorted(tech.items()):
        lvl = _dread_level(rec["dread"])
        techniques.append({
            "techniqueID": tid,
            "score": rec["count"],
            "color": _LEVEL_COLOUR.get(lvl, "#fef0d9"),
            "enabled": True,
            "comment": f"DREAD {rec['dread']:.1f} ({lvl}); actor(s): {', '.join(sorted(rec['actors']))}",
            "metadata": [{"name": "findings", "value": str(rec["count"])}],
        })

    max_score = max((r["count"] for r in tech.values()), default=1)
    return {
        "name": name,
        "description": description or f"JanuSec breach-assessment coverage — {len(techniques)} techniques observed.",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {"colors": ["#fef0d9", "#b30000"], "minValue": 0, "maxValue": max_score},
        "legendItems": [
            {"label": "critical", "color": _LEVEL_COLOUR["critical"]},
            {"label": "high", "color": _LEVEL_COLOUR["high"]},
            {"label": "medium", "color": _LEVEL_COLOUR["medium"]},
            {"label": "low", "color": _LEVEL_COLOUR["low"]},
        ],
        "sorting": 3,  # descending by score
        "hideDisabled": True,
    }
