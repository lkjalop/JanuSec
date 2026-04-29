"""
Section 1 — Incident Lifecycle (ISO 27035)
==========================================

v1 status: FULLY_IMPLEMENTED

Produces the ISO 27035-shaped lifecycle view: detect → contain → eradicate →
recover → post_incident_review. Plus an evidence-grounded timeline.

In v1 most lifecycle phase fields beyond ``detect`` start empty. The platform
doesn't know what containment actions the customer took unless they're recorded
elsewhere (their ITSM, EDR runbook). The analyst fills these in via overrides.
The point is to give the analyst a STRUCTURED form to fill, not to fabricate
the contents.

INPUTS
------
- narrative['discovery']               — populated by enrich_narrative()
- narrative['attack_narrative']        — pipeline-generated prose (optional)
- narrative['kill_chain_stage']        — string label
- evidence_rows                        — for timeline construction
- cluster.row_refs / cluster.kill_chain_stages — for phase tagging

OUTPUTS
-------
- title: "Incident Lifecycle (ISO 27035)"
- auto_output:
    - detect:               populated from narrative.discovery
    - contain:              empty arrays for human fill
    - eradicate:            empty arrays for human fill
    - recover:              empty arrays for human fill
    - post_incident_review: empty for human fill
    - timeline:             list of {ts, phase, event, evidence_refs, mitre_technique}
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def build_s1_incident_lifecycle(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    """Build Section 1: ISO 27035 incident lifecycle."""
    discovery = narrative.get("discovery") or {}
    kill_chain_stage = narrative.get("kill_chain_stage") or "unknown"

    detect_block = _build_detect_block(discovery, narrative)
    timeline = _build_timeline(evidence_rows, narrative, cluster)

    auto_output = {
        "detect":   detect_block,
        # Phases below start empty. Analyst fills via overrides.
        # See PATCH /sections/{id} endpoint and human_edits.append_override.
        "contain": {
            "actions":      [],
            "started_at":   None,
            "completed_at": None,
            "owner":        None,
            "notes":        "",
        },
        "eradicate": {
            "actions":      [],
            "started_at":   None,
            "completed_at": None,
            "owner":        None,
            "notes":        "",
        },
        "recover": {
            "actions":      [],
            "started_at":   None,
            "completed_at": None,
            "owner":        None,
            "notes":        "",
        },
        "post_incident_review": {
            "root_cause":            None,
            "contributing_factors":  [],
            "lessons_learned":       [],
            "what_worked_well":      [],
            "what_should_change":    [],
            "review_date":           None,
            "attendees":             [],
        },
        "timeline":             timeline,
        "kill_chain_stage":     kill_chain_stage,
        "narrative_summary":    (narrative.get("attack_narrative") or
                                 narrative.get("ioc_summary") or "")[:1000],
    }

    return {
        "title": "Incident Lifecycle (ISO 27035)",
        "auto_output": auto_output,
    }


def _build_detect_block(discovery: dict, narrative: dict) -> dict:
    """Map enrich_narrative()'s discovery block to ISO 27035 detect stage."""
    lag_seconds = discovery.get("lag_seconds_from_first_evidence")
    return {
        "method":               discovery.get("source") or "unknown",
        "reference":            discovery.get("who"),
        "detected_at":          discovery.get("when"),
        "first_evidence_at":    discovery.get("first_evidence_at"),
        "detection_lag_seconds": lag_seconds,
        "detection_lag_human":  _humanize_seconds(lag_seconds) if lag_seconds else None,
        "discovery_channel":    _classify_discovery_channel(discovery.get("source") or ""),
    }


def _classify_discovery_channel(source: str) -> str:
    """Map raw discovery source to a small enumeration the UI can colour-code.

    Important context for the report: external pentest discovery is a
    different audit-defensibility story than EDR detection. It tells the
    auditor 'we did not detect this in our SOC; an external party did.'
    """
    s = source.lower()
    if "pentest" in s or "red_team" in s or "redteam" in s:
        return "external_assessor"
    if "edr" in s or "detection" in s or "soc" in s:
        return "internal_soc"
    if "analyst" in s:
        return "internal_analyst"
    if "deterministic" in s or "pipeline" in s:
        return "platform_correlation"
    if "tip" in s or "intelligence" in s or "threat_intel" in s:
        return "external_threat_intel"
    return "unknown"


def _build_timeline(
    evidence_rows: list[dict],
    narrative: dict,
    cluster: dict,
) -> list[dict]:
    """Construct an ordered timeline from evidence rows.

    Pulls the highest-significance rows (limited to ~50) and orders them
    chronologically. Tags each entry with kill-chain phase if available.
    """
    if not evidence_rows:
        return _fallback_timeline_from_narrative(narrative)

    cluster_phases = cluster.get("kill_chain_stages") or []
    phase_by_index: dict[int, str] = {}
    if isinstance(cluster_phases, list):
        for i, phase_info in enumerate(cluster_phases):
            if isinstance(phase_info, dict):
                for ridx in (phase_info.get("row_indices") or []):
                    try:
                        phase_by_index[int(ridx)] = str(phase_info.get("phase") or "")
                    except (TypeError, ValueError):
                        pass

    items: list[dict] = []
    for r in evidence_rows:
        ts = (r.get("timestamp") or r.get("eventTime") or
              r.get("published") or r.get("CreationTime") or
              r.get("@timestamp"))
        if not ts:
            continue
        ridx = _row_index(r)
        event_label = _describe_row(r)
        technique = _row_technique(r)
        items.append({
            "ts":              ts,
            "phase":           phase_by_index.get(ridx) if ridx is not None else None,
            "event":           event_label[:200],
            "evidence_refs":   [ridx] if ridx is not None else [],
            "mitre_technique": technique,
            "source":          r.get("_source") or r.get("source"),
        })

    items.sort(key=lambda x: x["ts"])

    # Cap timeline length — this is a summary, not a full event log.
    # The auditor can request a deeper view via the RAG sidebar.
    if len(items) > 50:
        items = items[:25] + items[-25:]
    return items


def _fallback_timeline_from_narrative(narrative: dict) -> list[dict]:
    """If no evidence rows are passed, build a minimal timeline from
    narrative.discovery so the section isn't completely empty."""
    discovery = narrative.get("discovery") or {}
    items: list[dict] = []
    if discovery.get("first_evidence_at"):
        items.append({
            "ts":              discovery["first_evidence_at"],
            "phase":           "initial_access",
            "event":           "First evidence observed",
            "evidence_refs":   [],
            "mitre_technique": None,
            "source":          None,
        })
    if discovery.get("when"):
        items.append({
            "ts":              discovery["when"],
            "phase":           "discovery",
            "event":           f"Incident discovered via {discovery.get('source', 'unknown')}",
            "evidence_refs":   [],
            "mitre_technique": None,
            "source":          None,
        })
    return items


def _row_index(row: dict) -> int | None:
    for k in ("row_index", "row_number", "id", "evidence_id"):
        v = row.get(k)
        if v is None:
            continue
        try:
            return int(float(v))
        except (TypeError, ValueError):
            continue
    return None


def _row_technique(row: dict) -> str | None:
    v = row.get("mitre_technique") or row.get("technique_id")
    if isinstance(v, list) and v:
        return str(v[0]).upper()
    if isinstance(v, str) and v:
        return v.upper()
    return None


def _describe_row(row: dict) -> str:
    """Produce a one-line human description of an event row."""
    parts: list[str] = []
    src = row.get("_source") or row.get("source")
    if src:
        parts.append(f"[{src}]")
    evt = (row.get("eventName") or row.get("event_simpleName") or
           row.get("Operation") or row.get("eventType"))
    if evt:
        parts.append(str(evt))
    user = row.get("user_name") or row.get("userName") or row.get("username")
    if user and user not in ("-", "n/a", ""):
        parts.append(f"by {user}")
    host = row.get("hostname") or row.get("ComputerName") or row.get("host")
    if host:
        parts.append(f"on {host}")
    desc = row.get("description") or row.get("analyst_notes")
    if desc and not parts:
        parts.append(str(desc)[:120])
    return " ".join(parts) if parts else "(event)"


def _humanize_seconds(s: int | float | None) -> str:
    if s is None:
        return ""
    try:
        s = int(s)
    except (TypeError, ValueError):
        return ""
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    days = s // 86400
    hours = (s % 86400) // 3600
    return f"{days}d {hours}h"
