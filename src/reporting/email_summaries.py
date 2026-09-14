from __future__ import annotations

from typing import Any, Dict, Optional


def _get(ev: Any, key: str, default: Any = None) -> Any:
    try:
        if isinstance(ev, dict):
            return ev.get(key, default)
        return getattr(ev, key, default)
    except Exception:
        return default


def tier1_summary(event, chain_record: Optional[Any] = None) -> Dict[str, Any]:
    dep = {
        "identity": bool(chain_record and any(getattr(s, "domain", "") == "identity" for s in getattr(chain_record, "stages", []) or [])),
        "devops": bool(chain_record and any(getattr(s, "domain", "") == "devops" for s in getattr(chain_record, "stages", []) or [])),
        "endpoint": bool(chain_record and any(getattr(s, "domain", "") == "endpoint" for s in getattr(chain_record, "stages", []) or [])),
    }
    subject = _get(event, "subject", "")
    sender = _get(event, "sender", {})
    auth_failed = bool(_get(event, "auth_failed", False))
    url_risk = (_get(event, "raw_event", {}) or {}).get("url_enrichment")
    click_context = (_get(event, "raw_event", {}) or {}).get("click_events")
    evidence = []
    if auth_failed:
        evidence.append("Authentication controls did not validate cleanly.")
    if url_risk:
        evidence.append("URLs in the message require review or enrichment.")
    if click_context:
        evidence.append("User click activity was observed and should be reviewed.")
    if dep["identity"] or dep["devops"] or dep["endpoint"]:
        evidence.append("Related downstream telemetry exists beyond the email itself.")
    if not evidence:
        evidence.append("Initial mail hygiene checks did not surface strong corroborating issues.")
    human_summary = (
        f"Tier 1 triage reviewed '{subject or 'untitled message'}' and found "
        f"{'authentication or trust concerns' if auth_failed or url_risk else 'no immediate high-confidence trust failure'}."
    )
    return {
        "message_id": _get(event, "message_id"),
        "subject": subject,
        "sender": sender,
        "auth": {
            "spf": _get(event, "spf_result"),
            "dkim": _get(event, "dkim_result"),
            "dmarc": _get(event, "dmarc_result"),
            "auth_failed": auth_failed,
            "alignment": _get(event, "alignment_status"),
        },
        "url_risk": url_risk,
        "human_report": bool(_get(event, "human_reported", False)),
        "click_context": click_context,
        "dependency_status": dep,
        "chain_stage": "email",
        "summary_text": human_summary,
        "evidence_basis": evidence,
        "recommended": [
            {"action": "Quarantine Similar", "priority": "high"} if dep["identity"] or dep["devops"] else {"action": "Open Investigation", "priority": "medium"}
        ],
        "confidence": (getattr(chain_record, "confidence", 0.0) if chain_record else 0.0),
    }


def tier2_summary(event, chain_record: Optional[Any] = None) -> Dict[str, Any]:
    timeline = []
    if chain_record:
        for s in getattr(chain_record, "stages", []) or []:
            timeline.append({"domain": getattr(s, "domain", ""), "event_id": getattr(s, "event_id", ""), "timestamp": getattr(s, "timestamp", 0.0), "confidence": getattr(s, "confidence", 0.0)})
    base = tier1_summary(event, chain_record)
    timeline = []
    if chain_record:
        for s in getattr(chain_record, "stages", []) or []:
            timeline.append({"domain": getattr(s, "domain", ""), "event_id": getattr(s, "event_id", ""), "timestamp": getattr(s, "timestamp", 0.0), "confidence": getattr(s, "confidence", 0.0)})
    supply_chain = {
        "targets_developer": bool(_get(event, "targets_developer", False)),
        "oauth_scopes": (_get(event, "raw_event", {}) or {}).get("oauth_scopes"),
        "repo_activity": (_get(event, "raw_event", {}) or {}).get("repo_activity"),
        "package_activity": (_get(event, "raw_event", {}) or {}).get("package_activity"),
        "endpoint_traces": (_get(event, "raw_event", {}) or {}).get("endpoint_traces"),
        "sandbox": (_get(event, "raw_event", {}) or {}).get("sandbox_enrichment"),
    }
    next_steps = [
        "Review the strongest evidence before escalating to containment.",
        "Confirm whether the same sender, URL, or host appears in identity or endpoint telemetry.",
    ]
    if timeline:
        next_steps.append("Use the timeline to validate whether activity spread across domains or stayed isolated.")
    return {
        **base,
        "supply_chain": {
            **supply_chain,
        },
        "timeline": timeline,
        "volatility_hint": (_get(event, "raw_event", {}) or {}).get("overlap_volatility"),
        "summary_text": (
            base.get("summary_text", "")
            + " Tier 2 enrichment adds cross-domain context, related telemetry, and recommended next investigative steps."
        ).strip(),
        "next_steps": next_steps,
    }


__all__ = ["tier1_summary", "tier2_summary"]
