from typing import List, Dict, Any


def categorize_reports(reports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Return mapping of attention queues to report_ids.

    Queues: urgent_incidents, suspicious_unconfirmed, policy_gaps, dependency_issues, followups_pending
    """
    buckets = {
        "urgent_incidents": [],
        "suspicious_unconfirmed": [],
        "policy_gaps": [],
        "dependency_issues": [],
        "followups_pending": [],
    }

    for rpt in reports:
        rid = rpt.get("report_id")
        severity = (rpt.get("risk_quantification", {}).get("severity") or "LOW").upper()
        verdict = (rpt.get("verdict", {}).get("final_verdict") or "REVIEW").upper()
        confidence = float(rpt.get("verdict", {}).get("final_confidence", 0.0))
        dep_status = rpt.get("dependency_status", {})
        has_fail = any(m.get("status") == "FAIL" for m in rpt.get("framework_mappings", []))

        if severity in ("CRITICAL", "HIGH") and verdict == "THREAT":
            buckets["urgent_incidents"].append(rid)
        if verdict in ("SUSPICIOUS", "REVIEW") and confidence < 0.75:
            buckets["suspicious_unconfirmed"].append(rid)
        if has_fail:
            buckets["policy_gaps"].append(rid)
        if dep_status and dep_status.get("seconds_since_ok", 0) > 600:
            buckets["dependency_issues"].append(rid)
        if len(rpt.get("decision_gates", [])) > 0:
            buckets["followups_pending"].append(rid)

    return buckets
