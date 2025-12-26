"""Hunt Report Generator

Generates JSON (dict) & Markdown representations from a HuntSession
and supplementary data (future: coverage deltas, anomalies, lineage hashes).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

REQUIRED_SECTIONS = [
    'session_id','tenant','window_hours','duration_seconds','estimate_units','actual_units',
    'delta_pct','factors','model_tiers_used','status'
]

def to_json(session_report: dict[str, Any]) -> dict[str, Any]:
    missing = [k for k in REQUIRED_SECTIONS if k not in session_report]
    return {
        'report': session_report,
        'missing_sections': missing,
        'generated_at': datetime.utcnow().isoformat()+'Z'
    }

def to_markdown(session_report: dict[str, Any]) -> str:
    lines = [f"# Hunt Session Report: {session_report.get('session_id')}\n"]
    lines.append(f"Tenant: `{session_report.get('tenant')}`  Window Hours: {session_report.get('window_hours')}  Status: **{session_report.get('status')}**\n")
    lines.append("## Cost Summary")
    lines.append(f"Estimated Units: {session_report.get('estimate_units')}  Actual Units: {session_report.get('actual_units')}  Delta %: {session_report.get('delta_pct')}\n")
    lines.append("## Model Tiers Used")
    mt = session_report.get('model_tiers_used', {})
    if not mt:
        lines.append("(none)\n")
    else:
        for tier, count in sorted(mt.items()):
            lines.append(f"- Tier {tier}: {count} selections")
    lines.append("\n## Factors")
    factors = session_report.get('factors', {})
    if not factors:
        lines.append("(no factors)\n")
    else:
        for k,v in factors.items():
            lines.append(f"- {k}: {v}")
    lines.append("\n## Timing")
    lines.append(f"Duration Seconds: {session_report.get('duration_seconds')}")
    lines.append("\n---\nGenerated via hunt_report module\n")
    return '\n'.join(lines)
