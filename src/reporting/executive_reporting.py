from __future__ import annotations

import os
import json
import sqlite3
import time
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from src.reporting.persona_template_packs import enrich_canonical_report
from src.reporting.persona_views import generate_persona_view


REVIEW_STATE_ORDER = [
    "reviewed_benign",
    "reviewed_false_positive",
    "needs_investigation",
    "confirmed_malicious",
    "out_of_scope",
    "duplicate",
    "unknown",
]

TREND_WINDOWS = [
    ("24h", 24 * 3600),
    ("72h", 72 * 3600),
    ("5_business_days", 5 * 24 * 3600),
    ("weekend", 2 * 24 * 3600),
    ("14d", 14 * 24 * 3600),
    ("30d", 30 * 24 * 3600),
]

DOMAIN_LABELS = {
    "identity": "identity and access",
    "cloud": "cloud control plane",
    "network": "network traffic",
    "endpoint": "endpoint activity",
    "data": "data access",
    "email": "email activity",
    "api": "application and API activity",
    "app": "application activity",
    "remote": "remote access",
}

SOURCE_LABEL_HINTS = [
    ("entra_signin", "cloud sign-in telemetry"),
    ("signin", "cloud sign-in telemetry"),
    ("entra_audit", "identity audit telemetry"),
    ("audit", "identity audit telemetry"),
    ("conditional_access", "conditional-access telemetry"),
    ("identity_protection", "identity-risk telemetry"),
    ("activity", "cloud activity telemetry"),
    ("defender", "cloud-detection telemetry"),
    ("guardduty", "cloud-detection telemetry"),
    ("securityhub", "cloud-security telemetry"),
    ("cloudtrail", "cloud activity telemetry"),
    ("nsg_flow", "network flow telemetry"),
    ("vpc_flow", "network flow telemetry"),
    ("flow", "network flow telemetry"),
]

PROVIDER_STYLE = {
    "Azure": {"chip": "AZURE", "accent": "#1f5fbf"},
    "AWS": {"chip": "AWS", "accent": "#c26a00"},
    "Oracle": {"chip": "OCI", "accent": "#b4442d"},
    "VMware": {"chip": "VMWARE", "accent": "#35736f"},
    "Nutanix": {"chip": "NUTANIX", "accent": "#5c5cb0"},
    "Hybrid / multi-cloud": {"chip": "HYBRID", "accent": "#6b5b95"},
    "Cloud": {"chip": "CLOUD", "accent": "#5b6773"},
}


def _slugify_token(value: Any) -> str:
    text = re.sub(r"[^a-z0-9._-]+", "-", str(value or "").strip().lower())
    return re.sub(r"-{2,}", "-", text).strip("-") or "unknown"


def build_executive_filename(artifact: Dict[str, Any], ext: str) -> str:
    ts = _row_ts({"ts": artifact.get("generated_at")}) or time.time()
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y.%m.%d-%H%MZ")
    tenant = _slugify_token((artifact.get("meta") or {}).get("tenant") or "unknown-tenant")
    persona = "executive"
    version = _slugify_token(artifact.get("artifact_version") or "v1").replace("executive-report-", "")
    if version.startswith("v"):
        version = version[1:]
    version = f"v{version or '1'}"
    return f"{stamp}-{tenant}-{persona}-{version}.{ext.lstrip('.')}"


def _pretty_domain(domain: Any) -> str:
    return DOMAIN_LABELS.get(str(domain or "").strip().lower(), str(domain or "").replace("_", " "))


def _pretty_source(source: Any) -> str:
    text = str(source or "").strip().lower()
    for needle, label in SOURCE_LABEL_HINTS:
        if needle in text:
            return label
    return text.replace("_", " ") or "telemetry"


def _claim_validate(field_name: str, value: str) -> str:
    """Phase-1 claim validator: replace empty/generic fields with structured INSUFFICIENT_EVIDENCE."""
    _CLAIM_MESSAGES = {
        "what_happened": (
            "INSUFFICIENT_EVIDENCE: LLM Tier-2 narrative not yet generated. "
            "Upload again with LLM_MOCK=0 to generate. ETA: +2 min. "
            "Deterministic summary: correlated activity detected across available telemetry sources."
        ),
        "why_it_matters": (
            "INSUFFICIENT_EVIDENCE: Business impact assessment not yet generated. "
            "Run with LLM_MOCK=0 for full analysis. ETA: +3 min. "
            "Interim: review DREAD composite score for risk estimate."
        ),
        "what_to_do_next": (
            "INSUFFICIENT_EVIDENCE: Action recommendation not yet generated. "
            "ETA: +2 min with LLM enabled. Interim: review triage table above for immediate actions."
        ),
    }
    _generic_prefixes = ("No ", "—", "N/A")
    if not value or not value.strip() or any(value.startswith(p) for p in _generic_prefixes):
        return _CLAIM_MESSAGES.get(field_name, f"INSUFFICIENT_EVIDENCE: {field_name} not available.")
    return value


def _synthesise_narrative(report: Dict[str, Any]) -> str:
    """P0-2: Deterministic fallback narrative — never show 'No narrative available'."""
    rq = report.get("risk_quantification") or {}
    severity = str(rq.get("severity") or report.get("severity") or "").upper()
    n_mal = int((report.get("canonical") or {}).get("suspicious_row_count") or 0)
    n_total = int(report.get("accepted_rows") or report.get("rows_processed") or 0)
    org = str(report.get("org") or report.get("tenant_name") or report.get("tenant_id") or "the dataset")
    # Try to derive from top factors
    top_factors = [(e.get("factor_name") or e.get("name") or str(e)) for e in
                   ((report.get("verdict") or {}).get("semantic_top_factors") or
                    (report.get("verdict") or {}).get("top_contributing_factors") or [])[:3]]
    factor_str = "; ".join(str(f) for f in top_factors if f) or "no high-confidence indicators"
    if not severity or severity in ("LOW", "NONE"):
        return (f"Assessment of {org} found no high-confidence threats in {n_total:,} records. "
                f"All signals reviewed: {factor_str}.")
    return (
        f"Assessment of {org} identified {severity}-severity activity across {n_total:,} records. "
        f"Leading signals: {factor_str}. "
        f"{'Immediate analyst review required.' if severity in ('CRITICAL', 'HIGH') else 'Monitoring recommended.'}"
    )


def _synthesise_why_it_matters(report: Dict[str, Any]) -> str:
    """P0-2: Deterministic business-context fallback — never show 'No business summary available'."""
    rq = report.get("risk_quantification") or {}
    severity = str(rq.get("severity") or report.get("severity") or "").upper()
    exp_loss = int(rq.get("expected_loss_usd") or 0)
    has_pii = any(
        str(row.get("source_kind") or "").lower() in ("email", "identity")
        for row in ((report.get("evidence_appendix") or {}).get("source_evidence_rows") or [])
        if isinstance(row, dict)
    )
    exposure = f"Estimated financial exposure: ${exp_loss:,}. " if exp_loss else ""
    pii_note = "Personal data may be in scope — GDPR/privacy assessment recommended. " if has_pii else ""
    if not severity or severity == "LOW":
        return f"No material risk identified. {pii_note}Continue monitoring."
    return (
        f"{exposure}{pii_note}"
        f"{'Uncontained incident — containment decisions required now.' if severity == 'CRITICAL' else 'Incident under investigation — escalation may be required.'}"
    )


def _provider_label(report: Dict[str, Any]) -> str:
    sources = " ".join(
        str(row.get("source_kind") or "")
        for row in ((report.get("evidence_appendix") or {}).get("source_evidence_rows") or [])
        if isinstance(row, dict)
    ).lower()
    provider_hits = {
        "Azure": any(token in sources for token in ("azure", "entra", "defender")),
        "AWS": any(token in sources for token in ("aws", "guardduty", "securityhub", "cloudtrail")),
        "Oracle": any(token in sources for token in ("oracle", "oci")),
        "VMware": any(token in sources for token in ("vmware", "vcenter")),
        "Nutanix": any(token in sources for token in ("nutanix", "prism")),
    }
    active = [name for name, matched in provider_hits.items() if matched]
    if len(active) > 1:
        return "Hybrid / multi-cloud"
    if active:
        return active[0]
    return "Cloud"


def _row_ts(row: Dict[str, Any]) -> float | None:
    for key in ("ts", "event_ts", "createdDateTime", "activityDateTime", "eventTimestamp", "time"):
        value = row.get(key)
        if value is None:
            continue
        try:
            if isinstance(value, (int, float)):
                return float(value)
            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            from datetime import datetime

            return datetime.fromisoformat(text).timestamp()
        except Exception:
            continue
    return None


def _review_state(row: Dict[str, Any]) -> str:
    raw = str(
        row.get("review_state")
        or row.get("triage_status")
        or row.get("label")
        or row.get("operator_label")
        or row.get("adjudication")
        or ""
    ).strip().lower()
    mapping = {
        "tp": "confirmed_malicious",
        "true_positive": "confirmed_malicious",
        "confirmed_malicious": "confirmed_malicious",
        "malicious": "confirmed_malicious",
        "confirmed": "confirmed_malicious",
        "fp": "reviewed_false_positive",
        "false_positive": "reviewed_false_positive",
        "false-positive": "reviewed_false_positive",
        "benign": "reviewed_benign",
        "reviewed_benign": "reviewed_benign",
        "tn": "reviewed_benign",
        "true_negative": "reviewed_benign",
        "needs_investigation": "needs_investigation",
        "review": "needs_investigation",
        "pending": "needs_investigation",
        "suspicious": "needs_investigation",
        "deferred": "needs_investigation",
        "duplicate": "duplicate",
        "out_of_scope": "out_of_scope",
        "oos": "out_of_scope",
    }
    return mapping.get(raw, "unknown")


def _label_to_review_state(label: Any) -> str:
    raw = str(label or "").strip().lower()
    mapping = {
        "tp": "confirmed_malicious",
        "true_positive": "confirmed_malicious",
        "confirmed_malicious": "confirmed_malicious",
        "malicious": "confirmed_malicious",
        "confirmed": "confirmed_malicious",
        "fp": "reviewed_false_positive",
        "false_positive": "reviewed_false_positive",
        "false-positive": "reviewed_false_positive",
        "benign": "reviewed_benign",
        "reviewed_benign": "reviewed_benign",
        "tn": "reviewed_benign",
        "needs_review": "needs_investigation",
        "needs_investigation": "needs_investigation",
        "review": "needs_investigation",
        "suspicious": "needs_investigation",
        "deferred": "needs_investigation",
        "duplicate": "duplicate",
        "out_of_scope": "out_of_scope",
        "oos": "out_of_scope",
    }
    return mapping.get(raw, "unknown")


def _extract_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(payload.get("assessment"), dict):
        return dict(payload["assessment"])
    if isinstance(payload.get("files"), list) and payload["files"]:
        first = payload["files"][0]
        if isinstance(first, dict) and isinstance(first.get("assessment"), dict):
            report = dict(first["assessment"])
            if isinstance(first.get("personas"), dict):
                report["_replay_personas"] = first["personas"]
            if isinstance(first.get("tier2"), dict):
                report["_replay_tier2"] = first["tier2"]
            if isinstance(first.get("playbook"), dict):
                report["_replay_playbook"] = first["playbook"]
            return report
    return dict(payload)


def _review_state_counts(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {key: 0 for key in REVIEW_STATE_ORDER}
    for row in rows:
        counts[_review_state(row)] = counts.get(_review_state(row), 0) + 1
    return counts


def _fetch_sqlite_labels(tenant: str | None) -> List[Dict[str, Any]]:
    paths = []
    env_path = os.getenv("DB_FALLBACK_PATH")
    if env_path:
        paths.append(env_path)
    paths.append("data/cache/fallback.sqlite")
    for raw_path in paths:
        try:
            if not os.path.exists(raw_path):
                continue
            conn = sqlite3.connect(raw_path, timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                if tenant:
                    cur = conn.execute(
                        """
                        SELECT event_id, decision_id, label, tenant_id, evidence, query_template, created_at
                        FROM decision_labels
                        WHERE tenant_id = ?
                        ORDER BY created_at DESC
                        LIMIT 5000
                        """,
                        (tenant,),
                    )
                else:
                    cur = conn.execute(
                        """
                        SELECT event_id, decision_id, label, tenant_id, evidence, query_template, created_at
                        FROM decision_labels
                        ORDER BY created_at DESC
                        LIMIT 5000
                        """
                    )
                return [dict(row) for row in cur.fetchall()]
            finally:
                conn.close()
        except Exception:
            continue
    return []


def _fetch_memory_labels() -> List[Dict[str, Any]]:
    try:
        from src.core.labels_store import LABELS

        out = []
        for rec in LABELS.recent(limit=5000):
            out.append(
                {
                    "event_id": rec.event_id,
                    "decision_id": rec.event_id,
                    "label": rec.label,
                    "tenant_id": None,
                    "evidence": None,
                    "query_template": None,
                    "created_at": rec.ts,
                }
            )
        return out
    except Exception:
        return []


def _latest_labels_for_events(report: Dict[str, Any], rows: List[Dict[str, Any]]) -> tuple[Dict[str, int], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    tenant = str(report.get("org") or report.get("tenant_id") or report.get("tenant_name") or "").strip() or None
    labels = _fetch_sqlite_labels(tenant)
    if not labels:
        labels = _fetch_memory_labels()
    latest_by_event: Dict[str, Dict[str, Any]] = {}
    for row in labels:
        event_id = str(row.get("event_id") or row.get("decision_id") or "").strip()
        if not event_id:
            continue
        existing = latest_by_event.get(event_id)
        ts = _row_ts({"ts": row.get("created_at")}) or 0.0
        if existing is None or ts >= (_row_ts({"ts": existing.get("created_at")}) or 0.0):
            latest_by_event[event_id] = row
    counts = {key: 0 for key in REVIEW_STATE_ORDER}
    if rows:
        for row in rows:
            event_id = str(row.get("id") or row.get("event_id") or row.get("fingerprint") or "").strip()
            label_row = latest_by_event.get(event_id) if event_id else None
            state = _label_to_review_state(label_row.get("label")) if label_row else _review_state(row)
            counts[state] = counts.get(state, 0) + 1
    else:
        counts = _review_state_counts(rows)
    return counts, latest_by_event, labels


def _workflow_from_label_rows(label_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    merged = {
        "user_contacted": False,
        "change_ticket_found": False,
        "owner_confirmed": False,
        "change_tickets": [],
    }
    for row in label_rows:
        raw = row.get("evidence")
        if not raw:
            continue
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            continue
        if not isinstance(parsed, dict):
            continue
        workflow = parsed.get("workflow") if isinstance(parsed.get("workflow"), dict) else parsed
        if not isinstance(workflow, dict):
            continue
        if workflow.get("user_contacted"):
            merged["user_contacted"] = True
        if workflow.get("change_ticket_found"):
            merged["change_ticket_found"] = True
        if workflow.get("owner_confirmed"):
            merged["owner_confirmed"] = True
        ticket = str(workflow.get("change_ticket") or "").strip()
        if ticket and ticket not in merged["change_tickets"]:
            merged["change_tickets"].append(ticket)
    merged["change_tickets"] = merged["change_tickets"][:5]
    return merged


def _trend_counts_from_labels(labels: List[Dict[str, Any]], end_ts: float) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for label, seconds in TREND_WINDOWS:
        bucket = {key: 0 for key in REVIEW_STATE_ORDER}
        start_ts = end_ts - float(seconds)
        for row in labels:
            ts = _row_ts({"ts": row.get("created_at")})
            if ts is None or ts < start_ts or ts > end_ts:
                continue
            bucket[_label_to_review_state(row.get("label"))] += 1
        out[label] = bucket
    return out


def _latest_ts(rows: List[Dict[str, Any]], field: str | None = None) -> float:
    values: List[float] = []
    for row in rows:
        if field:
            ts = _row_ts({"ts": row.get(field)})
        else:
            ts = _row_ts(row)
        if ts is not None:
            values.append(ts)
    return max(values) if values else 0.0


def _window_counts(rows: List[Dict[str, Any]], end_ts: float) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for label, seconds in TREND_WINDOWS:
        bucket = {key: 0 for key in REVIEW_STATE_ORDER}
        start_ts = end_ts - float(seconds)
        for row in rows:
            row_ts = _row_ts(row)
            if row_ts is None or row_ts < start_ts or row_ts > end_ts:
                continue
            bucket[_review_state(row)] = bucket.get(_review_state(row), 0) + 1
        out[label] = bucket
    return out


def _selected_alerts(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    findings.sort(
        key=lambda item: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(item.get("severity") or "").lower(), 0),
            float(item.get("confidence") or 0.0),
        ),
        reverse=True,
    )
    alerts = []
    for finding in findings:
        alerts.append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "entity": finding.get("entity"),
                "evidence": (finding.get("evidence") or [])[:3],
            }
        )
        if len(alerts) >= 5:
            break
    return alerts


def _build_evidence_lookup(report: Dict[str, Any]) -> tuple[Dict[str, str], List[Dict[str, Any]]]:
    appendix = report.get("evidence_appendix") or {}
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    lookup: Dict[str, str] = {}
    for idx, row in enumerate(evidence_rows, start=1):
        citation = f"E{idx}"
        row["_evidence_code"] = citation
        keys = {
            str(row.get("index") or "").strip(),
            str(row.get("_citation") or "").strip(),
            str(row.get("source_kind") or "").strip().lower(),
            str(row.get("resource") or "").strip().lower(),
            str(row.get("user") or "").strip().lower(),
            str(row.get("ip") or "").strip().lower(),
            str(row.get("correlation_id") or "").strip().lower(),
        }
        for key in keys:
            if key:
                lookup[key] = citation
    return lookup, evidence_rows


def _citations_from_values(values: List[Any], lookup: Dict[str, str]) -> List[str]:
    citations: List[str] = []
    for value in values:
        candidates = [
            str(value or "").strip(),
            str(value or "").strip().lower(),
        ]
        for key in candidates:
            citation = lookup.get(key)
            if citation and citation not in citations:
                citations.append(citation)
    return citations[:6]


def _citations_for_rows(rows: List[Dict[str, Any]]) -> List[str]:
    citations: List[str] = []
    for row in rows:
        citation = str(row.get("_evidence_code") or row.get("_citation") or "").strip()
        if citation and citation not in citations:
            citations.append(citation)
    return citations[:6]


def _evidence_refs_for_rows(rows: List[Dict[str, Any]]) -> List[str]:
    refs: List[str] = []
    for row in rows:
        citation = str(row.get("_evidence_code") or row.get("_citation") or "").strip()
        if citation:
            refs.append(citation)
    return refs[:6]


def _executive_title(report: Dict[str, Any]) -> str:
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    focus = (report.get("evidence_appendix") or {}).get("focus_cluster") or {}
    domains = [str(item).strip().lower() for item in (focus.get("domains") or []) if str(item).strip()]
    top_titles = [str(item.get("title") or "").strip() for item in findings[:5] if str(item.get("title") or "").strip()]
    joined_titles = " ".join(top_titles).lower()
    provider = _provider_label(report)
    cloud_scope = provider.lower() if provider == "Hybrid / multi-cloud" else provider

    if any(token in joined_titles for token in ("role", "privilege", "global admin", "admin")):
        return f"Suspicious privileged access activity in {cloud_scope}"
    if any(token in joined_titles for token in ("sign-in", "signin", "identity protection", "conditional access")):
        return f"Suspicious identity activity in {cloud_scope}"
    if any(token in joined_titles for token in ("vault", "secret", "key", "storage")):
        return f"Sensitive resource access sequence in {cloud_scope}"
    if any(token in joined_titles for token in ("flow", "egress", "exfil", "beacon")):
        return f"Correlated cloud and network activity in {cloud_scope}"
    if domains:
        pretty = " and ".join(_pretty_domain(item) for item in sorted(set(domains))[:2])
        return f"Correlated {pretty} activity requiring review"
    return "Correlated cloud security activity requiring review"


def _persona_headline(report: Dict[str, Any], persona: str) -> str:
    """P2-8: Persona-specific headline — substantively different per audience.

    Each persona's first sentence should be the one thing their role cares about most.
    """
    rq = report.get("risk_quantification") or {}
    csv_model = (report.get("canonical_report") or report).get("_csv_model") or {}
    n_mal = int(csv_model.get("malicious_count") or
                (report.get("verdict") or {}).get("confirmed_malicious") or
                (report.get("canonical") or {}).get("malicious_row_count") or 0)
    n_sus = int(csv_model.get("suspicious_count") or
                (report.get("canonical") or {}).get("suspicious_row_count") or 0)
    overall = str(rq.get("severity") or csv_model.get("overall_risk") or
                  (report.get("verdict") or {}).get("final_verdict") or "LOW").upper()
    exp_loss = int(rq.get("expected_loss_usd") or 0)
    has_pii = bool(csv_model.get("has_email") or csv_model.get("has_pii"))
    has_c2 = bool(csv_model.get("has_c2"))
    has_exfil = any("data_exfiltration_confirmed" in (ev.get("factors") or [])
                    for ev in (csv_model.get("evidence") or []))
    # Grab primary adversary IP for context
    attacker_ips = ((csv_model.get("attack_story") or {}).get("attacker_ips") or [])
    primary_ip = (attacker_ips[0] if attacker_ips else
                  (report.get("canonical") or {}).get("top_c2_ip") or "")
    # Hosts at risk
    all_hosts = (csv_model.get("attack_story") or {}).get("internal_hosts") or []
    _canonical_host = (report.get("canonical") or {}).get("host_most_affected") or ""
    host_summary = (f"{all_hosts[0]}" if len(all_hosts) == 1
                    else f"{len(all_hosts)} hosts" if len(all_hosts) > 1
                    else _canonical_host if _canonical_host else "affected systems")

    p = (persona or "executive").lower()

    if p in ("soc", "soc_analyst"):
        if n_mal > 0:
            actions = f"{n_mal} event{'s' if n_mal > 1 else ''} require immediate isolation"
            return (f"P1 — {actions} | {host_summary}"
                    + (f" | C2: {primary_ip}" if primary_ip else ""))
        if n_sus > 0:
            return f"P2 — {n_sus} suspicious event{'s need' if n_sus > 1 else ' needs'} investigation | No confirmed threat"
        return "P3 — No confirmed threats | Review complete — all events benign"

    if p in ("forensic", "forensics"):
        if n_mal > 0:
            return (f"Evidence chain: {n_mal} confirmed malicious event{'s' if n_mal > 1 else ''} on {host_summary}"
                    + (" | Exfiltration confirmed" if has_exfil else ""))
        if n_sus > 0:
            return f"Evidence under review: {n_sus} suspicious events — timeline confidence MEDIUM"
        return "Evidence chain: INTACT | No malicious activity confirmed in dataset"

    if p == "threat_hunter":
        if has_c2 and primary_ip:
            return f"Hunt pivot: C2 infrastructure {primary_ip} — expand hunt to related subnet and user scope"
        if n_mal > 0:
            return f"Technique cluster confirmed | {n_mal} malicious events — generate hunt hypotheses"
        return "Threat hunt: negative result — recommend baseline calibration"

    if p in ("ciso",):
        lines = []
        if overall in ("CRITICAL", "HIGH"):
            lines.append(f"{overall} incident")
        if has_exfil:
            lines.append("data exfiltration confirmed")
        elif has_pii:
            lines.append("PII in scope")
        if exp_loss:
            lines.append(f"exposure est. ${exp_loss:,}")
        if lines:
            return " | ".join(lines).capitalize() + " — executive decision required"
        if n_sus > 0:
            return "Under investigation — no confirmed breach yet | Monitoring active"
        return "No material risk confirmed | Current controls effective"

    if p in ("executive", "board"):
        if overall in ("CRITICAL",):
            return "Active security incident — customer data may be at risk — decision required now"
        if overall == "HIGH":
            return "Serious security incident — under active containment — board update recommended"
        if n_sus > 0:
            return "Suspected security activity — investigation in progress — no confirmed breach"
        return "Security review complete — no confirmed threats identified"

    if p in ("compliance", "audit", "grc"):
        if has_pii and n_mal > 0:
            return "GDPR Art.33 notification clock running — PII confirmed in scope — legal review required"
        if n_mal > 0:
            return f"Control failures confirmed: {n_mal} events — framework mapping and remediation required"
        return "Compliance review: no control failures confirmed | Documentation complete"

    # Fallback to generic title
    return _executive_title(report)


def _focus_cluster_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    appendix = report.get("evidence_appendix") or {}
    focus = appendix.get("focus_cluster") or {}
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    shared_pivots = [item for item in (appendix.get("shared_pivots") or []) if isinstance(item, dict)]
    sources = sorted({_pretty_source(row.get("source_kind")) for row in evidence_rows if row.get("source_kind")})
    domains = sorted({_pretty_domain(item) for item in (focus.get("domains") or []) if item})
    pivots = [str(item.get("pivot") or "").strip() for item in shared_pivots if str(item.get("pivot") or "").strip()][:3]
    citations = _citations_for_rows(evidence_rows)
    provider = _provider_label(report)
    summary = {
        "headline": "Why this cluster was prioritized",
        "narrative": (
            f"{len(evidence_rows)} related {provider.lower()} records were grouped because the same identity, IP address, or resource "
            f"appeared across multiple sources in one investigation window."
        ),
        "why_it_matters": (
            f"The strongest overlap was seen across {', '.join(sources[:3]) or 'multiple sources'}, "
            f"covering {', '.join(domains[:2]) or 'multiple areas'}."
        ),
        "entities": pivots,
        "evidence_refs": citations,
        "component_count": focus.get("component_count") or 0,
    }
    return summary


def _focus_cluster_explainability(report: Dict[str, Any]) -> Dict[str, str]:
    appendix = report.get("evidence_appendix") or {}
    focus = appendix.get("focus_cluster") or {}
    shared_pivots = [item for item in (appendix.get("shared_pivots") or []) if isinstance(item, dict)]
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    score = float(focus.get("score") or 0.0)
    sources = [str(v) for v in (focus.get("sources") or []) if str(v).strip()]
    domains = [str(v) for v in (focus.get("domains") or []) if str(v).strip()]
    components = int(focus.get("component_count") or 0)
    top_pivot = None
    if shared_pivots:
        top_pivot = sorted(shared_pivots, key=lambda item: (-int(item.get("support_count") or 0), str(item.get("pivot") or "")))[0]
    sensitive = [
        row for row in evidence_rows
        if float((((row.get("business_criticality") or {}).get("score")) or 0.0)) >= 0.74
    ]
    return {
        "Score": (
            f"Score {score:.2f} reflects the strongest correlated activity in the selected window"
            + (f", supported by {len(sources)} source types" if sources else "")
            + (f" and {len(sensitive)} higher-risk resources." if sensitive else ".")
        ),
        "Sources": (
            f"The top shared pivot {top_pivot.get('pivot')} appeared across {int(top_pivot.get('support_count') or 0)} source records."
            if top_pivot and top_pivot.get("pivot")
            else "These are the source systems that independently contributed to the strongest correlated cluster."
        ),
        "Domains": (
            f"This cluster spans {', '.join(domains[:3])}, which indicates the investigation is not limited to one isolated control surface."
            if domains
            else "The domain mix was not fully preserved in the canonical artifact."
        ),
        "Component Count": (
            f"{components} correlated groups were observed before prioritization; the strongest cluster was selected above lower-signal or background activity."
            if components
            else "No component-count detail was preserved in the current artifact."
        ),
    }


def _plain_english_alerts(report: Dict[str, Any], evidence_lookup: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    alerts: List[Dict[str, Any]] = []
    provider = _provider_label(report)
    seen_kinds: set[str] = set()
    for finding in findings:
        confidence = float(finding.get("confidence") or 0.0)
        review_state = str(finding.get("review_state") or "").strip().lower()
        if confidence < 0.65:
            continue
        if review_state == "reviewed_benign":
            continue
        title = str(finding.get("title") or "Security signal").strip()
        lower = title.lower()
        kind = "general"
        if "sign" in lower:
            kind = "signin"
            plain = "Risky sign-in activity"
            meaning = f"A {provider} identity was used in a way that did not fit the normal sign-in pattern."
            action = "Confirm whether the sign-in was approved and whether the account should be contained."
        elif "assumerole" in lower or "assume role" in lower:
            kind = "role_assumption"
            plain = "Unexpected role assumption was observed"
            meaning = f"A privileged {provider} role was assumed during the same investigated sequence."
            action = "Confirm whether the role use was authorized and review downstream activity from the assumed session."
        elif any(token in lower for token in ("role", "admin", "privilege")):
            kind = "privilege"
            plain = "Privileged access changed"
            meaning = f"Administrative permissions or access settings changed during the same {provider} sequence."
            action = "Validate the change owner and revoke or roll back unauthorized access."
        elif any(token in lower for token in ("bucket", "s3", "storage", "putbucketpolicy", "bucketpublicaccessgranted", "s3.2")):
            kind = "storage"
            plain = "Sensitive storage access changed"
            meaning = f"Protected cloud storage settings or access patterns changed during the investigated sequence."
            action = "Confirm the intended storage state and reverse unauthorized exposure."
        elif any(token in lower for token in ("vault", "secret", "key")):
            kind = "secret"
            plain = "Sensitive cloud resources were accessed"
            meaning = f"Secrets or protected {provider} resources were touched during the correlated sequence."
            action = "Confirm the access was expected and rotate exposed credentials if needed."
        elif any(token in lower for token in ("risk", "protection")):
            kind = "risk"
            plain = "Provider risk controls raised alerts"
            meaning = f"{provider} controls flagged behavior that was inconsistent with expected user activity."
            action = "Review the affected identity and verify whether additional accounts show the same pattern."
        elif any(token in lower for token in ("guardduty", "security hub", "securityhub", "toripcaller", "defender_incident", "defender incident")):
            kind = "provider_detection"
            plain = "Cloud detections confirmed the sequence"
            meaning = f"Native {provider} security detections supported the same activity seen in the access and network records."
            action = "Use the cloud provider findings to confirm severity and containment priority."
        elif any(token in lower for token in ("flow", "exfil", "egress", "vpc_flow", "vpc flow")):
            kind = "network"
            plain = "Related network transfer was observed"
            meaning = f"Network records in {provider} overlapped with the same identities, roles, or resources."
            action = "Confirm whether the destination and transfer volume were expected."
        else:
            plain = title[:1].upper() + title[1:]
            meaning = "This signal contributed to the correlated case and requires analyst validation."
            action = "Confirm whether the signal belongs to the same incident and whether escalation is required."
        if kind in seen_kinds:
            continue
        seen_kinds.add(kind)
        refs = _citations_from_values(
            [finding.get("title"), finding.get("entity"), *(finding.get("evidence") or [])],
            evidence_lookup,
        )
        alerts.append(
            {
                "title": plain,
                "meaning": meaning,
                "action": action,
                "status": str(finding.get("severity") or "unknown").upper(),
                "confidence": confidence,
                "evidence_refs": refs,
                "kind": kind,
            }
        )
        if len(alerts) >= 5:
            break
    appendix = report.get("evidence_appendix") or {}
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    if "network" not in seen_kinds:
        flow_rows = [row for row in evidence_rows if "flow" in str(row.get("source_kind") or "").lower()]
        if flow_rows and len(alerts) < 5:
            alerts.append(
                {
                    "title": "Related network transfer was observed",
                    "meaning": f"Network records in {provider} overlapped with the same identities, roles, or resources.",
                    "action": "Confirm whether the destination and transfer volume were expected.",
                    "status": "HIGH",
                    "confidence": max(float(row.get("confidence") or 0.0) for row in flow_rows) if flow_rows else 0.0,
                    "evidence_refs": _evidence_refs_for_rows(flow_rows[:4]),
                    "kind": "network",
                }
            )
            seen_kinds.add("network")
    return alerts


def _claim_business_effect(statement: str) -> str:
    text = statement.lower()
    if "access-control" in text or "privileged" in text:
        return "Administrative control over cloud resources may have been changed outside approved process."
    if "sensitive resource access" in text or "secret" in text:
        return "Sensitive systems, secrets, or protected data stores may require review and credential rotation."
    if "network flow" in text or "data movement" in text:
        return "There may be elevated risk of follow-on access, data handling concerns, or wider incident scope."
    if "business loss" in text:
        return "Current evidence does not yet support a quantified business impact."
    return "Requires business validation before operational or financial impact can be confirmed."


def _claim_owner_action(statement: str, status: str) -> str:
    text = statement.lower()
    if status == "unknown":
        return "Security operations: collect more evidence before escalating the claim."
    if "access-control" in text or "privileged" in text:
        return "IAM / cloud platform owner: confirm authorized change window and reverse unauthorized access."
    if "sensitive resource access" in text or "secret" in text:
        return "Application or platform owner: validate affected resource access and rotate exposed secrets if needed."
    if "network flow" in text or "data movement" in text:
        return "Network / incident response lead: confirm destination, scope, and containment requirements."
    return "Incident lead: validate the claim and assign the accountable owner."


def _areas_to_investigate(report: Dict[str, Any]) -> List[str]:
    appendix = report.get("evidence_appendix") or {}
    focus = appendix.get("focus_cluster") or {}
    domains = [str(item).strip().lower() for item in (focus.get("domains") or []) if str(item).strip()]
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    sources = {str(row.get("source_kind") or "").lower() for row in evidence_rows}
    provider = _provider_label(report)
    areas: List[str] = []
    if "identity" in domains:
        areas.append(f"Identity and access records in {provider} should be checked for related sign-ins, policy changes, and role assignments.")
    if "cloud" in domains:
        areas.append(f"Cloud control activity in {provider} should be checked for related administrative changes to the same users, roles, or resources.")
    if "network" in domains or any("flow" in item for item in sources):
        areas.append(f"Network and egress records linked to {provider} should be checked to confirm whether the same destinations appear before or after the core sequence.")
    if any(any(tag in str(row.get("resource") or "").lower() for tag in ("vault", "secret", "bucket", "storage", "key")) for row in evidence_rows):
        areas.append("Sensitive resource access should be checked to determine whether protected data, secrets, keys, or storage objects were accessed by related identities.")
    return areas[:4]


def _working_hypothesis(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    appendix = report.get("evidence_appendix") or {}
    evidence_rows = [row for row in (appendix.get("source_evidence_rows") or []) if isinstance(row, dict)]
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    texts = " ".join(str(item.get("title") or "") for item in findings).lower()
    has_identity = any((row.get("user") or row.get("actor")) for row in evidence_rows)
    has_flow = any("flow" in str(row.get("source_kind") or "").lower() for row in evidence_rows)
    has_privilege = "privilege" in texts or "role" in texts or "admin" in texts
    workflow = ((report.get("impact_metadata") or {}).get("analyst_workflow") or {})
    user_contacted = bool(workflow.get("user_contacted"))
    owner_confirmed = bool(workflow.get("owner_confirmed"))
    ticket_found = bool(workflow.get("change_ticket_found"))
    return [
        {
            "label": "Compromised identity likely",
            "status": "supported" if has_identity and has_privilege else "unknown",
            "note": "Current evidence is more consistent with account misuse than a single isolated alert.",
        },
        {
            "label": "Insider misuse established",
            "status": "not_established",
            "note": "Current evidence does not show intent or confirm whether the user action was authorized.",
        },
        {
            "label": "Authorized admin activity confirmed",
            "status": "supported" if owner_confirmed or ticket_found else "not_established",
            "note": "Analyst workflow evidence is present." if owner_confirmed or ticket_found else "Administrative approval or change-ticket evidence is not present in the current report artifact.",
        },
        {
            "label": "Broader impact still possible",
            "status": "supported" if has_flow else "unknown",
            "note": "Related network activity or additional access records should be checked before closing scope.",
        },
        {
            "label": "Affected user has been contacted",
            "status": "supported" if user_contacted else "not_established",
            "note": "User-contact evidence comes from analyst workflow fields, not from model inference.",
        },
    ]


def _business_outcomes_with_refs(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    appendix = report.get("evidence_appendix") or {}
    evidence_rows = appendix.get("source_evidence_rows") or []
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    outputs: List[Dict[str, Any]] = []

    access_control_rows = [
        row for row in evidence_rows
        if any(tag in str(row.get("source_kind") or "").lower() for tag in ("audit", "activity"))
    ]
    if any("role" in str(item.get("title") or "").lower() or "policy" in str(item.get("title") or "").lower() for item in findings):
        outputs.append(
            {
                "statement": "Privileged access governance was affected by observed role or policy changes.",
                "status": "confirmed",
                "evidence_refs": _evidence_refs_for_rows(access_control_rows),
            }
        )

    secret_rows = [
        row for row in evidence_rows
        if any(tag in str(row.get("resource") or "").lower() for tag in ("secret", "vault"))
    ]
    if secret_rows:
        outputs.append(
            {
                "statement": "Secret-management assets were accessed or modified in the same correlated sequence.",
                "status": "confirmed",
                "evidence_refs": _evidence_refs_for_rows(secret_rows),
            }
        )

    flow_rows = [
        row for row in evidence_rows
        if "flow" in str(row.get("source_kind") or "").lower()
    ]
    if flow_rows:
        outputs.append(
            {
                "statement": "Outbound network transfer followed the identity and cloud-control events, indicating possible data movement.",
                "status": "correlated",
                "evidence_refs": _evidence_refs_for_rows(flow_rows),
            }
        )
    return outputs


def _action_basis_refs(report: Dict[str, Any]) -> List[str]:
    appendix = report.get("evidence_appendix") or {}
    evidence_rows = appendix.get("source_evidence_rows") or []
    rows = [
        row for row in evidence_rows
        if any(tag in str(row.get("source_kind") or "").lower() for tag in ("audit", "activity", "flow"))
        or any(tag in str(row.get("resource") or "").lower() for tag in ("secret", "vault"))
    ]
    return _evidence_refs_for_rows(rows)


def _collect_framework_entries(report: Dict[str, Any]) -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = {
        "mitre_attack": [],
        "mitre_atlas": [],
        "owasp_api": [],
        "owasp_llm": [],
        "stride": [],
        "dread": [],
        "diamond": [],
        "pasta": [],
    }
    framework_mappings = report.get("framework_mappings") or []
    for item in framework_mappings:
        if not isinstance(item, dict):
            continue
        framework = str(item.get("framework") or item.get("name") or "").lower()
        code = item.get("control") or item.get("id") or item.get("technique") or item.get("value")
        if not code:
            continue
        if "atlas" in framework:
            out["mitre_atlas"].append(code)
        elif "owasp" in framework and "api" in framework:
            out["owasp_api"].append(code)
        elif "owasp" in framework and ("llm" in framework or "agent" in framework):
            out["owasp_llm"].append(code)
        elif "mitre" in framework:
            out["mitre_attack"].append(code)
        elif "stride" in framework:
            out["stride"].append(code)
        elif "diamond" in framework:
            out["diamond"].append(code)
        elif "pasta" in framework:
            out["pasta"].append(code)
        elif "dread" in framework:
            out["dread"].append(code)

    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        for token in finding.get("mitre") or []:
            if token:
                out["mitre_attack"].append(token)
        diamond = finding.get("diamond")
        if isinstance(diamond, dict) and diamond:
            out["diamond"].append(diamond)
        dread = finding.get("dread")
        if isinstance(dread, dict) and dread:
            out["dread"].append(dread)
        for stride in finding.get("stride") or finding.get("stride_heuristics") or []:
            if stride:
                out["stride"].append(stride)

    for row in report.get("rows") or []:
        if not isinstance(row, dict):
            continue
        for token in row.get("mitre") or []:
            if token:
                out["mitre_attack"].append(token)
        atlas = row.get("atlas") or row.get("mitre_atlas")
        if isinstance(atlas, list):
            out["mitre_atlas"].extend([item for item in atlas if item])
        elif atlas:
            out["mitre_atlas"].append(atlas)
        for key in ("owasp_api", "owasp_llm"):
            value = row.get(key)
            if isinstance(value, list):
                out[key].extend([item for item in value if item])
            elif value:
                out[key].append(value)
        dread = row.get("dread")
        if isinstance(dread, dict) and dread:
            out["dread"].append(dread)
        diamond = row.get("diamond")
        if isinstance(diamond, dict) and diamond:
            out["diamond"].append(diamond)
        for stride in row.get("stride") or row.get("stride_heuristics") or []:
            if stride:
                out["stride"].append(stride)
        pasta = row.get("pasta")
        if isinstance(pasta, list):
            out["pasta"].extend([item for item in pasta if item])
        elif pasta:
            out["pasta"].append(pasta)

    deduped: Dict[str, List[Any]] = {}
    for key, values in out.items():
        seen = set()
        items: List[Any] = []
        for value in values:
            marker = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
            if marker in seen:
                continue
            seen.add(marker)
            items.append(value)
        deduped[key] = items
    return deduped


def _framework_sections(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    collected = _collect_framework_entries(report)
    sections: List[Dict[str, Any]] = []

    attack_ids = []
    for item in collected["mitre_attack"]:
        text = str(item)
        if re.match(r"^T\d{4}(\.\d{3})?$", text):
            attack_ids.append(text)
    if attack_ids:
        sections.append(
            {
                "title": "MITRE ATT&CK",
                "summary": "Rendered only from ATT&CK techniques already present in the canonical artifact.",
                "items": sorted(attack_ids)[:12],
            }
        )

    if collected["mitre_atlas"]:
        sections.append(
            {
                "title": "MITRE ATLAS",
                "summary": "Rendered only from ATLAS mappings already present in the canonical artifact.",
                "items": [str(item) for item in collected["mitre_atlas"][:12]],
            }
        )

    if collected["owasp_api"]:
        sections.append(
            {
                "title": "OWASP API",
                "summary": "Rendered only from OWASP API mappings already present in the canonical artifact.",
                "items": [str(item) for item in collected["owasp_api"][:12]],
            }
        )

    if collected["owasp_llm"]:
        sections.append(
            {
                "title": "OWASP LLM / Agentic AI",
                "summary": "Rendered only from LLM or agentic-AI mappings already present in the canonical artifact.",
                "items": [str(item) for item in collected["owasp_llm"][:12]],
            }
        )

    if collected["stride"]:
        sections.append(
            {
                "title": "STRIDE",
                "summary": "Rendered only from STRIDE categories already present in the canonical artifact.",
                "items": [str(item) for item in collected["stride"][:8]],
            }
        )

    dread_items = [item for item in collected["dread"] if isinstance(item, dict)]
    if dread_items:
        averaged: Dict[str, float] = {}
        keys = ("damage", "repro", "exploitability", "users", "discoverability", "score")
        for key in keys:
            vals = []
            for item in dread_items:
                value = item.get(key)
                if isinstance(value, (int, float)):
                    vals.append(float(value))
            if vals:
                averaged[key] = round(sum(vals) / len(vals), 2)
        if averaged:
            sections.append(
                {
                    "title": "DREAD",
                    "summary": "Rendered only from DREAD fields already present in the canonical artifact.",
                    "items": [f"{key}: {value}" for key, value in averaged.items()],
                }
            )

    diamond_items = [item for item in collected["diamond"] if isinstance(item, dict)]
    if diamond_items:
        latest = diamond_items[0]
        sections.append(
            {
                "title": "Diamond Model",
                "summary": "Rendered only from Diamond-model fields already present in the canonical artifact.",
                "items": [f"{key}: {value}" for key, value in latest.items() if value][:6],
            }
        )

    if collected["pasta"]:
        sections.append(
            {
                "title": "PASTA",
                "summary": "Rendered only from PASTA fields already present in the canonical artifact.",
                "items": [str(item) for item in collected["pasta"][:8]],
            }
        )

    # Wire PASTA/Diamond/MAESTRO/DREAD for Cloud-v2 pipeline (generated inline when not in canonical)
    if not sections or not any(s["title"] in ("PASTA", "Diamond Model", "MAESTRO") for s in sections):
        _inline = _inline_threat_models(report)
        for sec in _inline:
            if not any(s["title"] == sec["title"] for s in sections):
                sections.append(sec)

    return sections


def _inline_threat_models(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate PASTA / Diamond / MAESTRO / DREAD threat model sections inline
    from scored assessment data. Used when the pipeline didn't run build_threat_models()."""
    sections: List[Dict[str, Any]] = []
    rq = report.get("risk_quantification") or {}
    verdict = report.get("verdict") or {}
    top_factors = [str(e.get("factor_name") or "") for e in (report.get("semantic_top_factors") or [])[:5] if e.get("factor_name")]
    impact = report.get("impact_metadata") or {}
    identities = sorted(impact.get("affected_identities") or [])[:4]
    hosts = sorted(impact.get("affected_hosts") or [])[:4]
    findings = (report.get("findings") or [])[:4]
    severity = str(rq.get("severity") or "LOW")
    confidence = float(verdict.get("final_confidence") or 0.0)
    attack_timeline = report.get("attack_timeline") or []
    provider = str(report.get("org") or report.get("tenant_name") or "the organization")
    clusters = report.get("investigation_clusters") or []
    cluster_entities = [str(c.get("pivot_entity") or "") for c in clusters if c.get("pivot_entity")][:4]

    # ── DREAD (if risk_quantification fields present) ──────────────────────
    damage = int(rq.get("damage_potential") or 0)
    repro = int(rq.get("reproducibility") or 0)
    exploitability = int(rq.get("exploitability") or 0)
    aff_users = int(rq.get("affected_users") or 0)
    discoverability = int(rq.get("discoverability") or 0)
    if any([damage, repro, exploitability, aff_users, discoverability]):
        total = damage + repro + exploitability + aff_users + discoverability
        sections.append({
            "title": "DREAD",
            "summary": f"DREAD risk score derived from scored findings. Total: {total}/50.",
            "items": [
                f"Damage: {damage}/10",
                f"Reproducibility: {repro}/10",
                f"Exploitability: {exploitability}/10",
                f"Affected Users: {aff_users}/10",
                f"Discoverability: {discoverability}/10",
                f"Total Score: {total}/50 — severity {severity}",
            ],
        })

    # ── Diamond Model ─────────────────────────────────────────────────────
    ext_ips = []
    for row in (report.get("rows") or []):
        dst = str(row.get("dst_ip") or row.get("dst_system") or "")
        if dst and not any(dst.startswith(p) for p in ("10.", "192.168.", "172.")):
            ext_ips.append(dst.split("(")[0].strip())
    ext_ips = sorted(set(ext_ips))[:3]
    infra = ", ".join(ext_ips) if ext_ips else "unknown"
    capab = ", ".join(set(top_factors[:4])) if top_factors else "unknown"
    victim_str = ", ".join(identities[:2] or hosts[:2]) if (identities or hosts) else "unknown"
    sections.append({
        "title": "Diamond Model",
        "summary": "Adversary–Capability–Infrastructure–Victim model derived from scored evidence.",
        "items": [
            f"Adversary: Unknown threat actor (infrastructure: {infra})",
            f"Capability: {capab}",
            f"Infrastructure: {infra}",
            f"Victim: {victim_str or provider}",
        ],
    })

    # ── MAESTRO stages ────────────────────────────────────────────────────
    _factor_str = " ".join(top_factors).lower()
    maestro_stages = []
    _stage_map = [
        ("Initial Access",       ["email:lookalike_domain", "email:phishing", "email:vendor_impersonation", "identity:cloud_signin_external"]),
        ("Execution",            ["endpoint:suspicious_process_path", "attachment:malicious", "endpoint:encoded_command"]),
        ("Persistence",          ["email:inbox_rule_creation", "cloud:privilege_change", "cloud:iam_change"]),
        ("Defense Evasion",      ["network:c2_jitter_evasion", "network:adaptive_ewma_regular_cadence"]),
        ("Credential Access",    ["endpoint:credential_dump", "endpoint:lsass"]),
        ("Lateral Movement",     ["network:lateral_movement_port", "network:lateral_movement"]),
        ("Exfiltration",         ["network:suspicious_external_ip", "network:tor_exit_node", "data_movement"]),
    ]
    for stage_name, stage_factors in _stage_map:
        matched = [f for f in top_factors if any(sf in f.lower() for sf in stage_factors)]
        if matched or any(sf.replace("_", " ") in _factor_str for sf in stage_factors):
            maestro_stages.append(f"{stage_name}: CONFIRMED — {', '.join(matched[:2]) or 'see factors'}")
        elif severity in ("CRITICAL", "HIGH") and stage_name in ("Lateral Movement", "Exfiltration"):
            maestro_stages.append(f"{stage_name}: POSSIBLE — high severity investigation")
    if maestro_stages:
        sections.append({
            "title": "MAESTRO Stages",
            "summary": "Kill-chain lifecycle stages detected based on factor evidence.",
            "items": maestro_stages,
        })

    # ── PASTA (7 stages) ─────────────────────────────────────────────────
    org_name = str(report.get("org") or "Organization")
    pasta_items = [
        f"Stage 1 — Define Objectives: {org_name} assets and data at risk",
        f"Stage 2 — Define Scope: {', '.join(sorted(set(impact.get('corroborating_domains') or [])))[:3] or 'multi-domain activity'}",
        f"Stage 3 — Decompose: {' → '.join(cluster_entities[:4]) if len(cluster_entities) > 1 else (cluster_entities[0] if cluster_entities else 'single pivot')}",
        f"Stage 4 — Threat Analysis: {severity} severity threat — {confidence:.0%} confidence",
        f"Stage 5 — Vulnerability Analysis: {', '.join(top_factors[:3]) or 'see findings'}",
        f"Stage 6 — Attack Modelling: detected {len(attack_timeline)} timeline events",
        f"Stage 7 — Risk Quantification: expected loss ${rq.get('expected_loss_usd') or 0:,}",
    ]
    sections.append({
        "title": "PASTA",
        "summary": "Process for Attack Simulation and Threat Analysis — derived from investigation findings.",
        "items": pasta_items,
    })

    return sections


def _adjudication_workflow(report: Dict[str, Any], rows: List[Dict[str, Any]], latest_labels: Dict[str, Dict[str, Any]], label_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    tenant = str(report.get("org") or report.get("tenant_id") or report.get("tenant_name") or "").strip() or None
    unlabeled_ids: List[str] = []
    for row in rows:
        event_id = str(row.get("id") or row.get("event_id") or row.get("fingerprint") or "").strip()
        if event_id and event_id not in latest_labels:
            unlabeled_ids.append(event_id)
    return {
        "tenant": tenant,
        "label_history_count": len(label_history),
        "report_event_count": len(rows),
        "report_event_labeled_count": len(rows) - len(unlabeled_ids),
        "report_event_unlabeled_count": len(unlabeled_ids),
        "recent_unlabeled_event_ids": unlabeled_ids[:10],
        "workflow": {
            "single_label_endpoint": "/api/v1/feedback/decision",
            "csv_import_endpoint": "/api/v1/labeling/import/csv",
            "csv_export_endpoint": f"/api/v1/labeling/export/csv?tenant_id={tenant}" if tenant else "/api/v1/labeling/export/csv",
            "list_endpoint": f"/api/v1/labeling/list?tenant_id={tenant}" if tenant else "/api/v1/labeling/list",
            "ui_endpoint": "/api/v1/labeling/ui",
        },
    }


def _persona_filtered_claims(claims: List[Dict[str, Any]], persona: str) -> List[Dict[str, Any]]:
    """P1-A: Return persona-relevant claims so each persona sees different confirmed_claims."""
    if not claims:
        return claims
    # Keyword sets per persona — claims matching these keywords are promoted to top
    _persona_keywords: Dict[str, tuple] = {
        "executive":     ("business", "financial", "revenue", "brand", "pii", "exfil", "gdpr", "breach", "data"),
        "ciso":          ("pii", "gdpr", "nis2", "regulation", "compliance", "risk", "exposure", "exfil", "lateral"),
        "soc_analyst":   ("event", "alert", "ioc", "indicator", "ip", "hash", "process", "rule", "sigma", "timeline"),
        "threat_hunter": ("ioc", "ttp", "mitre", "technique", "c2", "beacon", "lateral", "persistence", "hash"),
        "forensics":     ("artifact", "hash", "sha256", "disk", "memory", "dump", "chain", "custody", "acquisition"),
        "compliance":    ("gdpr", "nis2", "regulation", "art.33", "pii", "control", "audit", "policy", "soc2"),
        "audit":         ("control", "failure", "iam", "policy", "change", "ticket", "audit", "population"),
    }
    keywords = _persona_keywords.get(persona, ())
    if not keywords:
        return claims
    def _score(c: Dict[str, Any]) -> int:
        text = (str(c.get("claim") or "") + " " + str(c.get("status") or "")).lower()
        return sum(1 for kw in keywords if kw in text)
    sorted_claims = sorted(claims, key=_score, reverse=True)
    return sorted_claims


def _build_stakeholder_gate(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build stakeholder_now/stakeholder_wait lists from report severity."""
    severity = str((report.get("risk_quantification") or {}).get("severity") or "").upper()
    if severity == "CRITICAL":
        now = ["CISO", "SOC analyst", "IR lead", "Legal"]
        wait = ["Board", "PR"]
    elif severity in ("HIGH", "MEDIUM"):
        now = ["SOC analyst", "IR lead"]
        wait = ["CISO", "Legal"]
    else:
        now = []
        wait = ["SOC analyst"]
    return {"stakeholder_now": now, "stakeholder_wait": wait}


def build_executive_report_artifact(payload: Dict[str, Any], options: Dict[str, Any] | None = None) -> Dict[str, Any]:
    opts = dict(options or {})
    report = enrich_canonical_report(_extract_report(payload))
    report_id = report.get("report_id") or report.get("assessment_id") or f"exec-{int(time.time())}"
    rows = [row for row in (report.get("rows") or []) if isinstance(row, dict)]
    evidence_lookup, evidence_rows = _build_evidence_lookup(report)
    review_counts, latest_labels, label_history = _latest_labels_for_events(report, rows)
    workflow_from_labels = _workflow_from_label_rows(label_history)
    impact_metadata = dict(report.get("impact_metadata") or {})
    existing_workflow = dict(impact_metadata.get("analyst_workflow") or {})
    merged_workflow = {
        "user_contacted": bool(existing_workflow.get("user_contacted")) or bool(workflow_from_labels.get("user_contacted")),
        "change_ticket_found": bool(existing_workflow.get("change_ticket_found")) or bool(workflow_from_labels.get("change_ticket_found")),
        "owner_confirmed": bool(existing_workflow.get("owner_confirmed")) or bool(workflow_from_labels.get("owner_confirmed")),
        "change_tickets": list(dict.fromkeys([*(existing_workflow.get("change_tickets") or []), *(workflow_from_labels.get("change_tickets") or [])]))[:5],
    }
    impact_metadata["analyst_workflow"] = merged_workflow
    report["impact_metadata"] = impact_metadata
    end_ts = max(
        _latest_ts(rows),
        _latest_ts(label_history, "created_at"),
        time.time(),
    )
    window_counts = _trend_counts_from_labels(label_history, end_ts) if label_history else _window_counts(rows, end_ts)
    _active_persona = str(opts.get("persona") or "executive").lower()
    executive = generate_persona_view(report, persona=_active_persona, disclosure_level=2, top_n=6)
    appendix = report.get("evidence_appendix") or {}
    _all_claims = appendix.get("claim_register") or []
    # P1-A: Filter claims by persona so each persona sees different confirmed_claims
    claim_register = _persona_filtered_claims(_all_claims, _active_persona)
    business_outcomes = _business_outcomes_with_refs(report)
    frameworks = _framework_sections(report)
    adjudication = _adjudication_workflow(report, rows, latest_labels, label_history)
    # P2-8: Per-persona headline — substantively different per audience
    title = _persona_headline(report, _active_persona) or _executive_title(report)
    focus_cluster_summary = _focus_cluster_summary(report)
    focus_cluster_explainability = _focus_cluster_explainability(report)
    key_evidence = _plain_english_alerts(report, evidence_lookup)
    areas_to_investigate = _areas_to_investigate(report)
    hypothesis = _working_hypothesis(report)
    provider = _provider_label(report)
    checklist = {
        "include_overview": bool(opts.get("include_overview", True)),
        "include_claims": bool(opts.get("include_claims", True)),
        "include_selected_alerts": bool(opts.get("include_selected_alerts", True)),
        "include_review_state_chart": bool(opts.get("include_review_state_chart", True)),
        "include_trends": bool(opts.get("include_trends", True)),
        "include_threat_intel": bool(opts.get("include_threat_intel")),
        "include_geoip_asn": bool(opts.get("include_geoip_asn")),
        "include_appendix": bool(opts.get("include_appendix", True)),
        "include_technical_appendix": bool(opts.get("include_technical_appendix")),
    }
    artifact = {
        "report_type": "executive_report",
        "artifact_version": "executive-report-v3",
        "generated_at": time.time(),
        "report_id": report_id,
        "timeframe": opts.get("timeframe") or "24h",
        "selection_mode": opts.get("selection_mode") or "selected_key_alerts",
        "output_filenames": {},
        "checklist": checklist,
        "meta": {
            "tenant": report.get("org") or report.get("tenant_name") or report.get("tenant_id"),
            "source_report_id": report.get("report_id") or report.get("assessment_id"),
            "qa_review": report.get("qa_review") or {},
            "report_regeneration": report.get("report_regeneration") or {},
        },
        "overview": {
            "headline": title,
            "what_happened": (
                # P0-C: Wire T1/T2 LLM narrative — prefer grounded tier-2 narrative,
                # fall back to canonical plain-language llm_summary, then persona view
                (report.get("tier2_analysis") or {}).get("grounded_narrative")
                or (report.get("canonical") or {}).get("llm_summary")
                or executive.get("what_happened")
                # P0-2 fix: deterministic fallback from attack_narrative (set by csv_adapter)
                or report.get("attack_narrative")
                # Final fallback: synthesise from verdict + counts
                or _synthesise_narrative(report)
            ),
            "why_it_matters": (
                executive.get("why_it_matters")
                # P0-2 fix: synthesise a business summary when LLM not available
                or (report.get("canonical") or {}).get("layered_summary", {}).get("top_layer", {}).get("why_it_matters")
                or _synthesise_why_it_matters(report)
            ),
            "what_to_do_next": executive.get("what_to_do_next") or executive.get("operational_next_step"),
            "action_basis_refs": _action_basis_refs(report),
            "business_impact": executive.get("business_impact") or {},
            "control_posture": executive.get("control_posture") or {},
            "business_outcomes": business_outcomes,
            "focus_cluster_summary": focus_cluster_summary,
            "key_evidence_reviewed": key_evidence,
            "areas_to_investigate": areas_to_investigate,
            "working_hypothesis": hypothesis,
            "provider": provider,
            "stakeholder_gate": _build_stakeholder_gate(report),
        },
        "facts": {
            "review_state_counts": review_counts,
            "trend_windows": window_counts,
            "selected_alerts": key_evidence,
            "claim_register": claim_register,
            "focus_cluster": appendix.get("focus_cluster") or {},
            "shared_pivots": [item for item in (appendix.get("shared_pivots") or []) if str(item.get("type") or "") != "resource"],
            "framework_sections": frameworks,
            "adjudication": {
                "label_history_count": len(label_history),
                "latest_labels_for_report_events": latest_labels,
                "source": "decision_labels_or_memory" if label_history else "report_rows_fallback",
                "window_anchor_ts": end_ts,
                "workflow": adjudication,
            },
        },
        "appendix": {
            "evidence_appendix": {
                **appendix,
                "key_evidence_reviewed": key_evidence,
                "focus_cluster_explainability": focus_cluster_explainability,
                "source_rows": len(appendix.get("source_evidence_rows") or []),
            },
            "top_findings": (report.get("findings") or [])[:8],
            "tier2": report.get("_replay_tier2") or {},
            "playbook": report.get("_replay_playbook") or {},
        },
        "canonical_report": report,
    }
    artifact["output_filenames"] = {
        "pdf": build_executive_filename(artifact, "pdf"),
        "html": build_executive_filename(artifact, "html"),
        "docx": build_executive_filename(artifact, "docx"),
    }
    return artifact


def _render_count_table(counts: Dict[str, int]) -> str:
    rows = []
    for key in REVIEW_STATE_ORDER:
        rows.append(
            "<tr>"
            f"<td>{escape(key.replace('_', ' ').title())}</td>"
            f"<td>{int(counts.get(key, 0))}</td>"
            "</tr>"
        )
    return (
        "<table style='width:100%;border-collapse:collapse'>"
        "<thead><tr><th align='left'>Review state</th><th align='left'>Count</th></tr></thead>"
        "<tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_trend_charts(trend_windows: Dict[str, Dict[str, int]]) -> str:
    labels = [
        ("confirmed_malicious", "Confirmed", "#0d6b43"),
        ("needs_investigation", "Review", "#8a4b2a"),
        ("reviewed_false_positive", "False Positive", "#7b2e2e"),
        ("reviewed_benign", "Benign", "#4a6475"),
        ("unknown", "Unknown", "#9a8b79"),
    ]
    cards = []
    for window, counts in trend_windows.items():
        total = sum(int(counts.get(key, 0)) for key in REVIEW_STATE_ORDER) or 1
        segments = []
        legends = []
        for key, label, color in labels:
            value = int(counts.get(key, 0))
            pct = (value / total) * 100.0 if total else 0.0
            if value > 0:
                segments.append(f"<div class='trend-segment' style='width:{pct:.2f}%;background:{color}' title='{escape(label)}: {value}'></div>")
            legends.append(f"<span class='legend-chip'><span class='legend-dot' style='background:{color}'></span>{escape(label)} {value}</span>")
        segment_html = "".join(segments) if segments else "<div class='trend-segment' style='width:100%;background:#ddd'></div>"
        cards.append(
            "<article class='trend-card'>"
            f"<div class='trend-head'><strong>{escape(window)}</strong><span>{total} reviewed items</span></div>"
            f"<div class='trend-bar'>{segment_html}</div>"
            f"<div class='trend-legend'>{''.join(legends)}</div>"
            "</article>"
        )
    return "".join(cards)


def _format_report_ts(value: Any) -> str:
    ts = _row_ts({"ts": value})
    if ts is None:
        return "Not recorded"
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        return str(value)


def _render_simple_table(headers: List[str], rows: List[List[Any]]) -> str:
    body = []
    for row in rows:
        cells = "".join(f"<td>{escape(str(cell if cell is not None else ''))}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    if not body:
        colspan = max(1, len(headers))
        body.append(f"<tr><td colspan='{colspan}'>No entries.</td></tr>")
    head = "".join(f"<th align='left'>{escape(str(header))}</th>" for header in headers)
    return (
        "<table style='width:100%;border-collapse:collapse'>"
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _render_appendix_tables(appendix_payload: Dict[str, Any]) -> str:
    focus_cluster = appendix_payload.get("focus_cluster") or {}
    shared_pivots = appendix_payload.get("shared_pivots") or []
    timeline_rows = appendix_payload.get("timeline_evidence") or []
    source_rows = appendix_payload.get("source_evidence_rows") or []
    non_technical = appendix_payload.get("non_technical_findings") or []
    key_evidence = appendix_payload.get("key_evidence_reviewed") or []

    focus_explain = appendix_payload.get("focus_cluster_explainability") or {}

    parts = [
        "<article class='panel'><h3>Focus Cluster</h3>"
        + _render_simple_table(
            ["Metric", "Value", "Why It Matters"],
            [
                ["Score", focus_cluster.get("score"), focus_explain.get("Score", "")],
                ["Sources", ", ".join(str(v) for v in (focus_cluster.get("sources") or [])), focus_explain.get("Sources", "")],
                ["Domains", ", ".join(str(v) for v in (focus_cluster.get("domains") or [])), focus_explain.get("Domains", "")],
                ["Component Count", focus_cluster.get("component_count"), focus_explain.get("Component Count", "")],
            ],
        )
        + "</article>",
        "<article class='panel'><h3>Shared Pivots</h3>"
        + _render_simple_table(
            ["Pivot", "Type", "Sources", "Support Count"],
            [
                [
                    item.get("pivot"),
                    item.get("type"),
                    ", ".join(str(v) for v in (item.get("sources") or [])),
                    item.get("support_count"),
                ]
                for item in shared_pivots
                if isinstance(item, dict)
            ],
        )
        + "</article>",
        "<article class='panel'><h3>Timeline Evidence</h3>"
        + _render_simple_table(
            ["Time", "Entity", "Domain", "Confidence"],
            [
                [
                    _format_report_ts(item.get("ts")),
                    item.get("entity"),
                    item.get("domain") or item.get("domain_hint") or "Not recorded",
                    item.get("confidence") if item.get("confidence") is not None else item.get("confidence_label") or "Not recorded",
                ]
                for item in timeline_rows
                if isinstance(item, dict)
            ],
        )
        + "</article>",
        "<article class='panel'><h3>Evidence Rows</h3>"
        + _render_simple_table(
            ["Evidence", "Source", "Time", "User", "IP", "Resource", "Criticality", "Owner", "Review State"],
            [
                [
                    item.get("_citation") or f"E{item.get('index')}",
                    item.get("source_kind"),
                    _format_report_ts(item.get("timestamp")),
                    item.get("user") or "",
                    item.get("ip") or "",
                    item.get("resource") or "",
                    ((item.get("business_criticality") or {}).get("label") or ""),
                    ((item.get("asset_metadata") or {}).get("owner") or ""),
                    item.get("review_state") or "",
                ]
                for item in source_rows
                if isinstance(item, dict)
            ],
        )
        + "</article>",
        "<article class='panel'><h3>Key Evidence Reviewed</h3>"
        + _render_simple_table(
            ["Summary", "Why It Matters", "What To Do", "Evidence"],
            [
                [
                    item.get("title"),
                    item.get("meaning"),
                    item.get("action"),
                    _render_evidence_citations(item.get("evidence_refs") or []),
                ]
                for item in key_evidence
                if isinstance(item, dict)
            ],
        )
        + "</article>",
        "<article class='panel'><h3>Non-Technical Findings</h3>"
        + _render_simple_table(
            ["Claim", "Present", "Evidence Rule"],
            [
                [
                    item.get("claim"),
                    "Yes" if item.get("present") else "No",
                    item.get("evidence_rule"),
                ]
                for item in non_technical
                if isinstance(item, dict)
            ],
        )
        + "</article>",
    ]
    return "".join(parts)


def _render_evidence_citations(refs: List[Any]) -> str:
    tokens = [str(ref).strip() for ref in refs if str(ref).strip()]
    return ", ".join(tokens) if tokens else "No evidence citation attached."


def _render_status_badge(value: Any) -> str:
    text = str(value or "unknown").strip().lower() or "unknown"
    label = text.replace("_", " ").title()
    return f"<span class='status-chip status-{escape(text)}'>{escape(label)}</span>"


def _render_key_value_rows(rows: List[List[Any]]) -> str:
    body = []
    for label, value in rows:
        body.append(f"<div class='meta-row'><div class='meta-label'>{escape(str(label))}</div><div class='meta-value'>{escape(str(value))}</div></div>")
    return "".join(body)


# ── Factor badge colour mapping ───────────────────────────────────────────────
_FACTOR_BADGE_COLOURS: Dict[str, str] = {
    "email": "#d97706", "attachment": "#b45309", "cloud": "#7c3aed",
    "identity": "#1d4ed8", "network": "#059669", "endpoint": "#dc2626",
    "corr": "#0891b2", "sequence": "#db2777", "graph": "#65a30d",
}

def _factor_badge(factor_name: str) -> str:
    category = factor_name.split(":")[0] if ":" in factor_name else "other"
    colour = _FACTOR_BADGE_COLOURS.get(category, "#6b7280")
    label = factor_name.replace("_", " ").replace(":", "›")
    return f"<span style='display:inline-block;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:600;background:{colour};color:#fff;margin:2px'>{escape(label)}</span>"


def _render_cluster_panels(clusters: List[Dict[str, Any]]) -> str:
    """Render one <article> per investigation cluster for a war-room multi-panel view."""
    if not clusters:
        return ""
    parts = ["<section style='margin-top:22px'><h2 style='font-size:1.1rem;margin-bottom:12px'>Investigation Clusters</h2>"]
    parts.append("<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px'>")
    _sev_colours = {"CRITICAL": "#dc2626", "HIGH": "#d97706", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
    for cl in clusters:
        entity = str(cl.get("pivot_entity") or "Unknown")
        severity = str(cl.get("severity") or "LOW").upper()
        sev_colour = _sev_colours.get(severity, "#6b7280")
        factors = cl.get("top_factors") or []
        badge_strip = "".join(_factor_badge(f) for f in factors[:5])
        _no_factors_html = "<span style='color:#9ca3af;font-size:11px'>no scored factors</span>"
        badge_html = badge_strip if badge_strip else _no_factors_html
        timeline = cl.get("timeline_events") or []
        timeline_html = ""
        if timeline:
            timeline_html = "<ul style='font-size:11px;margin:6px 0 0 0;padding-left:16px'>"
            for ev in timeline[:5]:
                ts = str(ev.get("ts") or ev.get("timestamp") or "")[:16]
                desc = str(ev.get("description") or ev.get("summary") or ev.get("event_type") or "")[:80]
                timeline_html += f"<li><span style='color:#9ca3af'>{escape(ts)}</span> {escape(desc)}</li>"
            timeline_html += "</ul>"
        action = str(cl.get("recommended_action") or cl.get("action") or "Analyst review required.")
        confidence = cl.get("confidence")
        conf_txt = f" &nbsp;· {int(float(confidence)*100)}%" if confidence is not None else ""
        ioc_count = len(cl.get("iocs") or [])
        ioc_txt = f" &nbsp;· {ioc_count} IOC{'s' if ioc_count != 1 else ''}" if ioc_count else ""
        parts.append(
            f"<article style='border:1px solid #374151;border-radius:8px;padding:12px;background:#111827'>"
            f"<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:6px'>"
            f"<strong style='font-size:13px'>{escape(entity)}</strong>"
            f"<span style='font-size:11px;font-weight:700;color:{sev_colour}'>{escape(severity)}{conf_txt}{ioc_txt}</span>"
            f"</div>"
            f"<div style='margin:4px 0'>{badge_html}</div>"
            f"{timeline_html}"
            f"<p style='font-size:11px;margin:8px 0 0 0;border-top:1px solid #374151;padding-top:6px;color:#d1d5db'>"
            f"<strong>Action:</strong> {escape(action)}</p>"
            f"</article>"
        )
    parts.append("</div></section>")
    return "".join(parts)


def render_executive_report_html(artifact: Dict[str, Any]) -> str:
    overview = artifact.get("overview") or {}
    facts = artifact.get("facts") or {}
    appendix = artifact.get("appendix") or {}
    checklist = artifact.get("checklist") or {}
    meta = artifact.get("meta") or {}
    business_outcomes = ((overview.get("business_outcomes") or []) if isinstance(overview.get("business_outcomes"), list) else [])
    framework_sections = facts.get("framework_sections") or []
    adjudication = (facts.get("adjudication") or {}).get("workflow") or {}
    focus_cluster_summary = overview.get("focus_cluster_summary") or {}
    areas_to_investigate = overview.get("areas_to_investigate") or []
    provider = str(overview.get("provider") or "Cloud")
    provider_style = PROVIDER_STYLE.get(provider, PROVIDER_STYLE["Cloud"])
    hypothesis = overview.get("working_hypothesis") or []
    decision_value = _claim_validate("what_to_do_next", str(overview.get("what_to_do_next") or ""))
    if isinstance(decision_value, list):
        immediate_decision = ""
        immediate_decision_list = [str(item).strip() for item in decision_value if str(item).strip()]
    else:
        immediate_decision = str(decision_value).strip()
        immediate_decision_list = []
    already_done = []
    if focus_cluster_summary.get("narrative"):
        already_done.append("The strongest correlated cluster has been isolated across multiple telemetry sources.")
    if facts.get("review_state_counts"):
        already_done.append("Current records have been grouped and separated from unrelated background activity for review.")
    if (appendix.get("evidence_appendix") or {}).get("timeline_evidence"):
        already_done.append("A factual timeline was assembled from the available source records.")
    next_four_hours = areas_to_investigate or [
        "Confirm whether the affected identities, resources, and destinations appear elsewhere in the same timeframe.",
        "Validate whether the observed access changes and resource activity were approved.",
    ]
    still_unknown = [
        "Whether any data left the environment.",
        "Whether additional accounts or systems were affected outside the current evidence window.",
        "Whether the activity was authorized administrative work or malicious misuse.",
    ]
    if business_outcomes:
        still_unknown = [item for item in still_unknown if "authorized administrative work" not in item]

    claim_rows = []
    for claim in facts.get("claim_register") or []:
        status = str(claim.get("status") or "unknown").strip().lower()
        refs = _render_evidence_citations(claim.get("evidence_refs") or [])
        claim_rows.append(
            "<tr>"
            f"<td>{escape(str(claim.get('claim') or ''))}</td>"
            f"<td>{_render_status_badge(status)}</td>"
            f"<td>{escape(_claim_business_effect(str(claim.get('claim') or '')))}</td>"
            f"<td>{escape(_claim_owner_action(str(claim.get('claim') or ''), status))}</td>"
            f"<td>{escape(refs)}</td>"
            "</tr>"
        )
    trends_html = _render_trend_charts(facts.get("trend_windows") or {})
    business_rows = []
    for item in business_outcomes:
        refs = _render_evidence_citations(item.get("evidence_refs") or [])
        business_rows.append(
            "<li>"
            f"<strong>{escape(str(item.get('statement') or ''))}</strong> "
            f"{_render_status_badge(item.get('status') or 'unknown')}"
            f"<div class='small'><strong>Evidence:</strong> {escape(refs)}</div>"
            "</li>"
        )
    framework_html = []
    for section in framework_sections:
        items = "".join(f"<li>{escape(str(item))}</li>" for item in (section.get("items") or []))
        framework_html.append(
            "<article class='panel'>"
            f"<h3>{escape(str(section.get('title') or 'Framework'))}</h3>"
            f"<p class='small'>{escape(str(section.get('summary') or ''))}</p>"
            f"<ul>{items or '<li>No canonical mappings present.</li>'}</ul>"
            "</article>"
        )
    metadata_rows = _render_key_value_rows(
        [
            ["Tenant", meta.get("tenant") or "unknown"],
            ["Provider", provider],
            ["Report ID", artifact.get("report_id") or ""],
            ["Source assessment", meta.get("source_report_id") or ""],
            ["Timeframe", artifact.get("timeframe") or "24h"],
            ["Generated", _format_report_ts(artifact.get("generated_at"))],
            ["QA status", ((meta.get("qa_review") or {}).get("status") or "draft")],
            ["Business criticality", ((((artifact.get("canonical_report") or {}).get("impact_metadata") or {}).get("business_criticality") or {}).get("highest") or {}).get("label") or "not established"],
        ]
    )
    hypothesis_rows = "".join(
        f"<li><strong>{escape(str(item.get('label') or ''))}</strong> "
        f"{_render_status_badge(item.get('status') or 'unknown')}<div class='small'>{escape(str(item.get('note') or ''))}</div></li>"
        for item in hypothesis
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Executive Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{{--bg:#f3eee6;--ink:#12202c;--muted:#5b6773;--panel:#fffdf8;--border:#d5c7b6;--accent:#8a4b2a;--accent2:#1f5f5b;--soft:#efe4d7;}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Georgia,"Iowan Old Style","Palatino Linotype",serif;background:linear-gradient(180deg,#efe6d9 0%,#f8f4ee 100%);color:var(--ink)}}
.page{{max-width:1100px;margin:0 auto;padding:36px 28px 56px}}
.hero{{background:linear-gradient(135deg,var(--panel),#f6efe5);border:1px solid var(--border);border-radius:24px;padding:24px 28px;box-shadow:0 16px 40px rgba(37,31,24,.08)}}
.eyebrow{{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}}
.headline{{margin:10px 0 0;font-size:34px;line-height:1.08}}
.sub{{margin-top:14px;color:var(--muted);font-size:16px;line-height:1.6}}
.hero-grid{{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-top:18px;align-items:start}}
.stack{{display:grid;gap:18px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}}
.wide-grid{{display:grid;grid-template-columns:1.4fr .9fr;gap:18px;margin-top:18px;align-items:start}}
.panel{{background:var(--panel);border:1px solid var(--border);border-radius:20px;padding:20px 22px;box-shadow:0 10px 26px rgba(37,31,24,.05)}}
.meta-strip{{display:flex;gap:20px;flex-wrap:wrap;margin-top:18px;font-size:13px;color:var(--muted)}}
h2,h3,h4{{margin:0 0 12px}} table td,table th{{padding:8px 10px;border-bottom:1px solid #eadfce;font-size:14px;vertical-align:top}} ul{{margin:10px 0 0 18px}}
.badge{{display:inline-block;padding:5px 10px;border-radius:999px;background:#f2e3d0;border:1px solid var(--border);font-size:12px;margin:0 8px 8px 0}}
.status-chip{{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid var(--border);font-size:11px;letter-spacing:.08em;text-transform:uppercase}}
.status-confirmed{{color:#0d6b43}} .status-correlated{{color:#8a4b2a}} .status-unknown{{color:#7b2e2e}}
.status-supported{{color:#0d6b43}} .status-not_established{{color:#7b2e2e}}
.meta-row{{padding:10px 0;border-bottom:1px solid #eadfce}}
.meta-label{{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}}
.meta-value{{font-size:16px;font-weight:700;overflow-wrap:anywhere}}
.narrative-list li{{margin-bottom:10px}}
.evidence-card{{padding:14px 0;border-bottom:1px solid #eadfce}}
.evidence-card:last-child{{border-bottom:none;padding-bottom:0}}
.small{{font-size:13px;color:var(--muted);line-height:1.5}}
.section-split{{display:grid;grid-template-columns:1.3fr .7fr;gap:18px;margin-top:18px}}
.provider-chip{{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--border);background:white}}
.provider-dot{{width:10px;height:10px;border-radius:50%}}
.trend-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}
.trend-card{{padding:14px;border:1px solid #eadfce;border-radius:16px;background:#fcf8f1}}
.trend-head{{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-bottom:8px;color:var(--muted)}}
.trend-bar{{display:flex;height:14px;border-radius:999px;overflow:hidden;background:#ece2d5;margin-bottom:10px}}
.trend-segment{{height:100%}}
.trend-legend{{display:flex;flex-wrap:wrap;gap:8px}}
.legend-chip{{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);padding:3px 8px;border-radius:999px;background:white;border:1px solid #eadfce}}
.legend-dot{{width:8px;height:8px;border-radius:50%}}
.page-break{{break-before:page;page-break-before:always}}
@page{{size:A4;margin:16mm 14mm 16mm 14mm}}
@media print{{body{{background:white;color:#111}} .page{{max-width:none;padding:0}} .panel,.hero{{box-shadow:none}} .hero{{padding:18px 20px}} .headline{{font-size:28px}} .sub{{font-size:13px}} table td,table th{{font-size:11px;padding:6px 8px}} .badge{{font-size:10px;padding:4px 8px}}}}
@media(max-width:900px){{.grid,.hero-grid,.section-split,.trend-grid,.wide-grid{{grid-template-columns:1fr}} .headline{{font-size:30px}}}}
</style>
</head>
<body>
<div class="page">
  <section class="hero">
    <div class="eyebrow">Executive Report</div>
    <h1 class="headline">{escape(str(overview.get("headline") or "Executive assessment"))}</h1>
    <div class="sub">{escape(_claim_validate("what_happened", str(overview.get("what_happened") or "")))}</div>
    <div class="meta-strip">
      <div class="provider-chip"><span class="provider-dot" style="background:{provider_style['accent']}"></span>{escape(provider_style['chip'])}</div>
      <div><strong>Tenant:</strong> {escape(str(meta.get("tenant") or "unknown"))}</div>
      <div><strong>Timeframe:</strong> {escape(str(artifact.get("timeframe") or "24h"))}</div>
      <div><strong>Report ID:</strong> {escape(str(artifact.get("report_id") or ""))}</div>
      <div><strong>QA:</strong> {escape(str((meta.get("qa_review") or {}).get("status") or "draft"))}</div>
    </div>
  </section>
  {"<section class='wide-grid'>" if checklist.get("include_overview", True) else ""}
      <article class="panel">
        <h2>What We Found</h2>
        <p>{escape(_claim_validate("why_it_matters", str(overview.get("why_it_matters") or "")))}</p>
        <div class='small'><strong>Focus of investigation:</strong> {escape(str(focus_cluster_summary.get("narrative") or ""))}</div>
        <div class='small'><strong>Why this was prioritized:</strong> {escape(str(focus_cluster_summary.get("why_it_matters") or ""))}</div>
        <div class='small'><strong>Evidence:</strong> {escape(_render_evidence_citations(focus_cluster_summary.get("evidence_refs") or []))}</div>
      </article>
      <article class="panel">
        <h2>Report Metadata</h2>
        {metadata_rows}
      </article>
  {"</section>" if checklist.get("include_overview", True) else ""}
  {"<section class='wide-grid'>" if checklist.get("include_overview", True) else ""}
    <div class="stack">
      <article class="panel">
        <h2>Immediate Decision Required</h2>
        {("<ol>" + "".join(f"<li>{escape(item)}</li>" for item in immediate_decision_list) + "</ol>") if immediate_decision_list else f"<p>{escape(immediate_decision)}</p>"}
        <div class='small'><strong>Evidence basis:</strong> {escape(_render_evidence_citations(overview.get("action_basis_refs") or []))}</div>
        <div class="section-split">
          <div>
            <h3>Already Done</h3>
            <ul class="narrative-list">{"".join(f"<li>{escape(item)}</li>" for item in already_done) or "<li>No completed actions recorded.</li>"}</ul>
            <h3>Next 4 Hours</h3>
            <ul class="narrative-list">{"".join(f"<li>{escape(item)}</li>" for item in next_four_hours)}</ul>
          </div>
          <div>
            <h3>Still Unknown</h3>
            <ul class="narrative-list">{"".join(f"<li>{escape(item)}</li>" for item in still_unknown)}</ul>
          </div>
        </div>
      </article>
      <article class="panel">
        <h2>Business Outcomes Supported By Evidence</h2>
        <ul class="narrative-list">{"".join(business_rows) or "<li>No business outcome was asserted because the current evidence does not support one yet.</li>"}</ul>
      </article>
    </div>
    <aside class="stack">
      <article class="panel">
        <h2>Review State Counts</h2>
        {_render_count_table(facts.get("review_state_counts") or {{}})}
      </article>
      <article class="panel">
        <h2>Working Hypothesis</h2>
        <ul class="narrative-list">{hypothesis_rows or "<li>No working hypothesis available.</li>"}</ul>
      </article>
      <article class="panel">
        <h2>Related Areas To Check Next</h2>
        <ul class="narrative-list">{"".join(f"<li>{escape(item)}</li>" for item in areas_to_investigate) or "<li>No additional environment areas were identified from current evidence.</li>"}</ul>
      </article>
    </aside>
  {"</section>" if checklist.get("include_overview", True) else ""}
  {"<section class='grid'>" if checklist.get("include_claims", True) else ""}
  {("<article class='panel'><h2>Claims</h2><table style='width:100%;border-collapse:collapse'><thead><tr><th align='left'>Claim</th><th align='left'>Status</th><th align='left'>Possible business effect</th><th align='left'>Action / owner</th><th align='left'>Evidence</th></tr></thead><tbody>" + (''.join(claim_rows) or "<tr><td colspan='5'>No claims available.</td></tr>") + "</tbody></table></article>") if checklist.get("include_claims", True) else ""}
  {"</section>" if checklist.get("include_claims", True) else ""}
  {("<section class='panel' style='margin-top:18px'><h2>Trend Windows</h2><div class='trend-grid'>" + trends_html + "</div></section>") if checklist.get("include_trends", True) else ""}
  {_render_cluster_panels(artifact.get("canonical_report", {}).get("investigation_clusters") or [])}
  {("<section class='grid' style='margin-top:18px'><article class='panel'><h2>Adjudication Workflow</h2><p class='small'>Labels are sourced from the existing analyst labeling workflow, not from model guesses.</p><table style='width:100%;border-collapse:collapse'><tbody><tr><td>Tenant</td><td>" + escape(str(adjudication.get("tenant") or "unknown")) + "</td></tr><tr><td>Labels in history</td><td>" + escape(str(adjudication.get("label_history_count") or 0)) + "</td></tr><tr><td>Report events labeled</td><td>" + escape(str(adjudication.get("report_event_labeled_count") or 0)) + "</td></tr><tr><td>Report events unlabeled</td><td>" + escape(str(adjudication.get("report_event_unlabeled_count") or 0)) + "</td></tr><tr><td>Single-label endpoint</td><td>" + escape(str(((adjudication.get("workflow") or {}).get("single_label_endpoint") or ""))) + "</td></tr><tr><td>CSV import</td><td>" + escape(str(((adjudication.get("workflow") or {}).get("csv_import_endpoint") or ""))) + "</td></tr><tr><td>CSV export</td><td>" + escape(str(((adjudication.get("workflow") or {}).get("csv_export_endpoint") or ""))) + "</td></tr></tbody></table></article>" + ("<article class='panel'><h2>Framework Sections</h2>" + "".join(framework_html) + "</article>" if framework_html else "<article class='panel'><h2>Framework Sections</h2><p class='small'>No canonical framework mappings were present, so this section is intentionally omitted from the executive body.</p></article>") + "</section>")}
  {("<section class='page-break' style='margin-top:18px'><h2>Evidence Appendix</h2>" + _render_appendix_tables(appendix.get("evidence_appendix") or {}) + "</section>") if checklist.get("include_appendix", True) else ""}
</div>
</body>
</html>"""
    return html
