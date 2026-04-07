"""csv_adapter.py
================
Converts a CSV-pipeline assessment dict (as produced by
scripts/run_cyberstash_full_pipeline.py) into the canonical report payload
expected by src.reporting.executive_reporting.build_executive_report_artifact().

The adapter also accepts a pre-built canonical model (the ``model`` kwarg from
``_build_canonical_model``) and injects it as ``report._csv_model`` so that the
HTML persona section builders can consume richer IOC / timeline data without
re-deriving it.

Usage (from the pipeline shim)
-------------------------------
    rows    = assessment.get("llm_rows") or assessment.get("rows") or []
    model   = _build_canonical_model(rows, filename)
    payload = csv_assessment_to_v3_payload(assessment, filename, persona, model=model)
    artifact = build_executive_report_artifact(payload, options={"include_trends": False})
    html    = render_executive_report_html(artifact, persona=persona)
"""
from __future__ import annotations

import re
import time
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VERDICT_TO_REVIEW_STATE: dict[str, str] = {
    "malicious":  "confirmed_malicious",
    "suspicious": "needs_investigation",
    "good":       "reviewed_benign",
    "benign":     "reviewed_benign",
    "unknown":    "unknown",
}

_RISK_LOSS: dict[str, int] = {
    "CRITICAL": 90_000,
    "HIGH":     35_000,
    "MEDIUM":   12_000,
    "LOW":       2_500,
}
_RISK_LOSS_MAX: dict[str, int] = {
    "CRITICAL": 270_000,
    "HIGH":     105_000,
    "MEDIUM":    36_000,
    "LOW":        7_500,
}

_SHEET_TO_DOMAIN: dict[str, str] = {
    "email":    "email",
    "network":  "network",
    "endpoint": "endpoint",
    "edr":      "endpoint",
    "cloud":    "cloud",
    "identity": "identity",
    "auth":     "identity",
    "c2":       "network",
}


# ---------------------------------------------------------------------------
# Row-level helpers
# ---------------------------------------------------------------------------

def _map_row(raw: dict, index: int, filename: str) -> dict:
    """Map a single CSV-pipeline row to the v3-compatible event row format."""
    verdict = str(raw.get("verdict") or "unknown").lower()
    row = dict(raw)
    row.update({
        # V3 review state
        "review_state":      _VERDICT_TO_REVIEW_STATE.get(verdict, "unknown"),
        # Source provenance
        "source_kind":       (raw.get("_sheet") or raw.get("source_kind")
                              or raw.get("export_source") or "csv"),
        "source_file":       filename,
        # Timestamp aliases used by v3 evidence builders
        "createdDateTime":   raw.get("ts") or raw.get("timestamp") or "",
        "event_ts":          raw.get("ts") or raw.get("timestamp") or "",
        # Identity aliases
        "userPrincipalName": (raw.get("user") or raw.get("username")
                              or raw.get("to") or raw.get("email_to") or ""),
        "ipAddress":         raw.get("src_ip") or raw.get("ip") or "",
        # Resource alias
        "resource":          (raw.get("process_name") or raw.get("process")
                              or raw.get("subject") or raw.get("path") or ""),
        # Evidence code
        "_evidence_code":    raw.get("_evidence_code") or f"E{index:02d}",
    })
    return row


# ---------------------------------------------------------------------------
# Pivots / appendix builders
# ---------------------------------------------------------------------------

def _classify_entity(entity: str) -> str:
    """Return the v3 pivot type for an IOC entity string."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", entity):
        return "ip"
    if "@" in entity:
        return "user"
    if "." in entity and not entity.startswith("\\") and len(entity) < 64:
        return "domain"
    return "process"


def _build_shared_pivots(model: dict) -> list[dict]:
    """Convert _build_canonical_model pivots to the v3 shared_pivots format."""
    out: list[dict] = []
    for pv in (model.get("pivots") or []):
        entity = str(pv.get("entity") or "")
        codes  = pv.get("codes") or []
        if not entity or not codes:
            continue
        out.append({
            "pivot":          entity,
            "type":           _classify_entity(entity),
            "sources":        ["csv"],
            "support_count":  len(codes),
            "evidence_codes": codes[:5],
        })
    return out[:8]


def _infer_domains(ev_list: list) -> list[str]:
    domains: set[str] = set()
    for ev in ev_list:
        sheet = (ev.get("sheet") or "").lower()
        domains.add(_SHEET_TO_DOMAIN.get(sheet, "data"))
    return sorted(domains) or ["data"]


def _normalize_confidence_band(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    mapping = {
        "confirmed": "Observed",
        "observed": "Observed",
        "supported": "Supported",
        "likely": "Likely",
        "suspected": "Likely",
        "unknown": "Unknown",
        "not_established": "Not established",
        "not established": "Not established",
    }
    return mapping.get(text, "Unknown")


def _claim_status_from_band(band: str) -> str:
    mapping = {
        "Observed": "confirmed",
        "Supported": "supported",
        "Likely": "correlated",
        "Unknown": "unknown",
        "Not established": "not_established",
    }
    return mapping.get(str(band or "").strip(), "unknown")


def _factor_set(evidence: list[dict]) -> set[str]:
    return {
        str(factor).lower()
        for item in evidence
        for factor in (item.get("factors") or [])
        if str(factor or "").strip()
    }


def _codes_for_factors(evidence: list[dict], tokens: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    lowered = tuple(token.lower() for token in tokens)
    for item in evidence:
        factors = [str(factor).lower() for factor in (item.get("factors") or [])]
        if any(any(token in factor for token in lowered) for factor in factors):
            code = item.get("code")
            if code and code not in matches:
                matches.append(code)
    return matches[:5]


def _claim_blueprints(model: dict) -> list[dict]:
    evidence = model.get("evidence") or []
    factors = _factor_set(evidence)
    strong_malicious_codes = _codes_for_factors(
        evidence,
        (
            "cloud:access_key_creation",
            "cloud:privilege_change",
            "email:auth_alignment_fail",
            "attachment:malicious_detonation",
            "network:lateral_movement_port",
            "data:dlp_policy_match",
            "context:missing_change_record",
        ),
    )
    malicious_codes = [e.get("code") for e in evidence if e.get("verdict") == "malicious"][:5]
    suspicious_codes = [e.get("code") for e in evidence if e.get("verdict") == "suspicious"][:5]
    c2_strong_codes = _codes_for_factors(
        evidence,
        ("c2", "beacon", "adaptive_ewma_regular_cadence"),
    )
    c2_weak_codes = _codes_for_factors(
        evidence,
        ("suspicious_external_ip",),
    )
    phishing_codes = _codes_for_factors(
        evidence,
        ("email:phishing_lure", "email:auth_alignment_fail", "attachment:autoexec_macro", "attachment:malicious_detonation"),
    )
    email_codes = [e.get("code") for e in evidence if (e.get("sheet") or "").lower() == "email"][:5]
    regulated_data_codes = _codes_for_factors(
        evidence,
        ("data:dlp_policy_match", "data:policy_gap"),
    )
    sensitive_data_codes = _codes_for_factors(evidence, ("data:sensitive_data_access",))
    has_sensitive_data_signal = any(token in factors for token in (
        "data:sensitive_data_access",
        "data:dlp_policy_match",
        "data:policy_gap",
    ))
    has_regulated_data_signal = any(token in factors for token in (
        "data:dlp_policy_match",
        "data:policy_gap",
    ))
    has_phishing_signal = any(token in factors for token in (
        "email:phishing_lure",
        "email:auth_alignment_fail",
        "attachment:autoexec_macro",
        "attachment:malicious_detonation",
    ))
    has_strong_malicious_signal = bool(strong_malicious_codes)
    # model.malicious_count is the workbook-level confirmed malicious count; use it
    # to elevate confidence when CSV evidence verdicts alone are insufficient
    # (e.g. all events scored 'suspicious' by raw factor scoring but workbook
    # review_state reports confirmed_malicious > 0).
    _wb_malicious_count = int(model.get("malicious_count") or 0)
    return [
        {
            "claim": "Malicious activity was observed in the dataset.",
            "claim_type": "incident_presence",
            "confidence_band": (
                "Observed" if has_strong_malicious_signal else
                "Supported" if malicious_codes or _wb_malicious_count >= 1 else
                "Likely" if suspicious_codes else
                "Unknown"
            ),
            "evidence_codes": strong_malicious_codes or malicious_codes or suspicious_codes,
            "missing_telemetry": [],
            "human_gate": "investigate",
            "approval_required": "none",
            "last_safe_statement": (
                "Multiple high-signal findings were observed in the dataset."
                if has_strong_malicious_signal else
                "At least one dataset row was marked malicious and still requires analyst validation."
                if malicious_codes else
                "The dataset contains suspicious activity that requires analyst review."
            ),
            "evidence_rule": "Observed requires high-signal malicious factors, not just a high severity label.",
        },
        {
            "claim": "A command-and-control channel may be present.",
            "claim_type": "command_and_control",
            "confidence_band": (
                "Supported"
                if c2_strong_codes and model.get("has_network") and model.get("has_endpoint")
                else "Likely"
                if c2_strong_codes or (len(c2_weak_codes) >= 2 and model.get("has_network") and model.get("has_endpoint"))
                else "Unknown"
            ),
            "evidence_codes": c2_strong_codes or c2_weak_codes,
            "missing_telemetry": [] if c2_strong_codes and model.get("has_network") and model.get("has_endpoint") else [
                "Proxy or firewall egress logs",
                "DNS or secure web gateway telemetry",
                "Byte-count metadata for outbound sessions",
            ],
            "human_gate": "investigate",
            "approval_required": "IR lead" if (c2_strong_codes or c2_weak_codes) else "none",
            "last_safe_statement": (
                "The dataset contains indicators consistent with outbound command-and-control traffic."
                if c2_strong_codes else
                "The dataset contains external communication signals that need command-and-control validation."
                if c2_weak_codes else
                "No command-and-control channel is established from the current dataset."
            ),
            "evidence_rule": "Requires network indicators and corroborating telemetry before containment-only language is promoted.",
        },
        {
            "claim": "A phishing or social-engineering delivery vector is in scope.",
            "claim_type": "initial_access",
            "confidence_band": "Supported" if phishing_codes else ("Likely" if has_phishing_signal or email_codes else "Unknown"),
            "evidence_codes": phishing_codes or email_codes,
            "missing_telemetry": [] if phishing_codes else [
                "Mail headers with SPF, DKIM, and DMARC results",
                "URL click telemetry or browser history",
                "Attachment detonation or sandbox verdict",
            ],
            "human_gate": "investigate",
            "approval_required": "none",
            "last_safe_statement": (
                "Email indicators consistent with phishing or social engineering are present."
                if phishing_codes else
                "Email activity is present and may warrant phishing validation."
                if email_codes else
                "No phishing delivery vector is established from the current dataset."
            ),
            "evidence_rule": "Supported requires phishing-aligned email factors, not just any email row.",
        },
        {
            "claim": "Personal data may be in scope.",
            "claim_type": "data_scope",
            "confidence_band": (
                "Observed"
                if has_regulated_data_signal else
                "Supported"
                if len(sensitive_data_codes) >= 2 else
                "Likely"
                if has_sensitive_data_signal or model.get("has_pii") else
                "Unknown"
            ),
            "evidence_codes": regulated_data_codes or sensitive_data_codes or email_codes[:3],
            "missing_telemetry": [] if has_regulated_data_signal else ["Data-classification or record-of-processing context"],
            "human_gate": "hold",
            "approval_required": "legal" if has_regulated_data_signal else "none",
            "last_safe_statement": (
                "Sensitive or regulated data indicators are present in the uploaded dataset."
                if has_regulated_data_signal else
                "Sensitive data access indicators are present, but regulated-data scope is not fully established."
                if has_sensitive_data_signal else
                "Email addresses are present in the uploaded dataset, but regulated data scope is not established."
                if model.get("has_pii") else
                "Personal-data scope is not established from the current dataset."
            ),
            "evidence_rule": "Observed requires DLP or policy-enforcement signals; isolated sensitivity hints are weaker evidence.",
        },
        {
            "claim": "Data exfiltration to an external attacker occurred.",
            "claim_type": "exfiltration",
            "confidence_band": "Unknown",
            "evidence_codes": [],
            "missing_telemetry": [
                "Proxy or firewall egress logs",
                "DNS or secure web gateway telemetry",
                "Byte-count metadata for outbound sessions",
            ],
            "human_gate": "hold",
            "approval_required": "IR lead",
            "last_safe_statement": "The current dataset does not establish data exfiltration.",
            "evidence_rule": "Requires outbound transfer evidence; absent from this dataset.",
        },
        {
            "claim": "A persistence mechanism was installed.",
            "claim_type": "persistence",
            "confidence_band": "Unknown",
            "evidence_codes": [],
            "missing_telemetry": [
                "Registry autoruns or service creation telemetry",
                "Scheduled-task creation logs",
                "Startup-folder or autorun artifact collection",
            ],
            "human_gate": "hold",
            "approval_required": "IR lead",
            "last_safe_statement": "The current dataset does not establish persistence.",
            "evidence_rule": "Requires autorun, service, or scheduled-task evidence; absent from this dataset.",
        },
    ]


def _build_non_technical(model: dict) -> list[dict]:
    findings = []
    for claim in _claim_blueprints(model):
        band = _normalize_confidence_band(claim.get("confidence_band"))
        findings.append({
            "claim": claim.get("claim"),
            "present": band in ("Observed", "Supported", "Likely"),
            "confidence_band": band,
            "missing_telemetry": claim.get("missing_telemetry") or [],
            "human_gate": claim.get("human_gate") or "investigate",
            "approval_required": claim.get("approval_required") or "none",
            "last_safe_statement": claim.get("last_safe_statement") or "",
            "evidence_rule": claim.get("evidence_rule") or "",
        })
    return findings


def _build_appendix(rows: list[dict], model: dict, filename: str) -> dict:
    """Build a fully-populated evidence_appendix compatible with the v3 engine."""
    ev_list = model.get("evidence") or []
    atk     = model.get("attack_story") or {}

    # Source evidence rows (drives Claims table + Evidence Appendix panels)
    src_ev_rows: list[dict] = []
    for i, ev in enumerate(ev_list[:20], start=1):
        r = ev.get("row") or {}
        exact_columns = sorted(
            str(key) for key, value in r.items()
            if value not in (None, "", [], {}, "?", "unknown", "—")
            and not str(key).startswith("_")
        )
        missing_key_fields = [
            field for field in ("host", "hostname", "user", "src_ip", "dst_ip", "process", "process_name", "sha256", "ts")
            if not r.get(field)
        ]
        src_ev_rows.append({
            "_citation":            ev.get("code") or f"E{i:02d}",
            "_evidence_code":       ev.get("code") or f"E{i:02d}",
            "index":                i,
            "row_index":            r.get("_row_index") or i,
            "source_kind":          ev.get("sheet") or "csv",
            "source_sheet":         ev.get("sheet") or r.get("_sheet") or "csv",
            "source_file":          filename,
            "timestamp":            r.get("ts") or r.get("timestamp"),
            "user":                 (r.get("user") or r.get("username")
                                     or r.get("to") or r.get("email_to") or ""),
            "ip":                   r.get("src_ip") or r.get("dst_ip") or "",
            "resource":             (r.get("process_name") or r.get("process")
                                     or r.get("subject") or r.get("path") or ""),
            "review_state":         _VERDICT_TO_REVIEW_STATE.get(
                                        ev.get("verdict", "unknown"), "unknown"),
            "business_criticality": {"label": ev.get("severity") or ""},
            "asset_metadata":       {"owner": r.get("user") or ""},
            "confidence_label":     ev.get("verdict") or "unknown",
            "domain_hint":          ev.get("sheet") or "csv",
            "activity":             (ev.get("summary")
                                     or (ev.get("factors") or ["event"])[0]
                                     if ev.get("factors") else "event"),
            "exact_columns_used":   exact_columns,
            "missing_key_fields":   missing_key_fields,
        })

    # Timeline evidence (sorted by timestamp)
    sorted_ev = atk.get("sorted_events") or ev_list
    timeline_ev: list[dict] = []
    for ev in sorted_ev[:12]:
        r = ev.get("row") or {}
        timeline_ev.append({
            "ts":              r.get("ts") or r.get("timestamp"),
            "entity":          (r.get("src_ip") or r.get("user")
                                 or r.get("process_name") or ""),
            "domain":          ev.get("sheet") or "csv",
            "confidence":      (ev.get("dread", 0.0) / 10.0
                                 if ev.get("dread") else None),
            "confidence_label": ev.get("verdict") or "unknown",
        })

    # Claims register
    claim_register: list[dict] = []
    for c in _claim_blueprints(model):
        band = _normalize_confidence_band(c.get("confidence_band"))
        claim_register.append({
            "claim": c.get("claim", ""),
            "claim_type": c.get("claim_type") or "claim",
            "confidence_band": band,
            "status": _claim_status_from_band(band),
            "evidence_refs": c.get("evidence_codes") or [],
            "missing_telemetry": c.get("missing_telemetry") or [],
            "human_gate": c.get("human_gate") or "investigate",
            "approval_required": c.get("approval_required") or "none",
            "last_safe_statement": c.get("last_safe_statement") or "",
        })

    # Focus cluster
    sources = sorted({ev.get("sheet") or "csv" for ev in ev_list})
    n_mal   = model.get("malicious_count") or 0
    fc_score = round(len(ev_list) * 0.15 + n_mal * 0.3, 2)

    # Shared pivots
    shared_pivots = _build_shared_pivots(model)
    if not shared_pivots:
        # Fallback: synthesise from IOC lists
        iocs = model.get("iocs") or {}
        for ip in (iocs.get("ips") or iocs.get("public_ips") or [])[:4]:
            shared_pivots.append({
                "pivot": ip, "type": "ip", "sources": sources, "support_count": 2,
            })
        for proc in (iocs.get("processes") or [])[:3]:
            shared_pivots.append({
                "pivot": proc, "type": "process", "sources": sources, "support_count": 1,
            })

    return {
        "report_id":              "",
        "generated_at":           time.time(),
        "factuality_contract": {
            "derived_only_from_report":                         True,
            "no_unattributed_claims":                           True,
            "business_loss_requires_existing_quantification":   True,
        },
        "shared_pivots":           shared_pivots,
        "raw_shared_pivots":       [],
        "focus_cluster": {
            "score":           fc_score,
            "sources":         sources,
            "domains":         _infer_domains(ev_list),
            "component_count": 1,
        },
        "timeline_evidence":       timeline_ev,
        "source_evidence_rows":    src_ev_rows,
        "non_technical_findings":  _build_non_technical(model),
        "claim_register":          claim_register,
        "key_evidence_reviewed":   [],
        "focus_cluster_explainability": {
            "Score":           "Derived from malicious event count and telemetry breadth.",
            "Sources":         "Sheet tabs from the uploaded CSV/XLSX file.",
            "Domains":         "Inferred from sheet names (email, network, endpoint, …).",
            "Component Count": "Single ingested file — treated as one correlated cluster.",
        },
    }


# ---------------------------------------------------------------------------
# Assessment-aware model builders
# ---------------------------------------------------------------------------

def _select_assessment_rows(assessment: dict) -> list[dict]:
    rows = assessment.get("rows") or []
    llm_rows = assessment.get("llm_rows") or []
    if rows:
        return [row for row in rows if isinstance(row, dict)]
    if llm_rows and any(
        any(key in row for key in ("event_id", "src_ip", "dst_ip", "hostname", "user_principal_name", "from_address"))
        for row in llm_rows if isinstance(row, dict)
    ):
        return [row for row in llm_rows if isinstance(row, dict)]
    return []


def _verdict_from_finding(finding: dict) -> str:
    confidence = float(finding.get("confidence") or 0.0)
    severity = str(finding.get("severity") or "").lower()
    factors = {str(factor).lower() for factor in (finding.get("factors") or []) if str(factor or "").strip()}
    strong_malicious = any(token in factors for token in {
        "cloud:access_key_creation",
        "cloud:privilege_change",
        "email:auth_alignment_fail",
        "attachment:malicious_detonation",
        "network:lateral_movement_port",
    })
    medium_malicious = any(token in factors for token in {
        "endpoint:suspicious_process_path",
        "endpoint:repeated_hash",
        "data:dlp_policy_match",
        "context:missing_change_record",
        "identity:conditional_access_failure",
        "network:suspicious_external_ip",
    })
    if strong_malicious and confidence >= 0.72:
        return "malicious"
    if confidence >= 0.86 and medium_malicious and severity in {"high", "critical"}:
        return "malicious"
    if confidence >= 0.55 or severity in {"medium", "high", "critical"}:
        return "suspicious"
    return "unknown"


# Hard IOC cutoff windows (Phase-1): stale observables are excluded before reporting
_IOC_CUTOFF_DAYS: dict[str, int | None] = {
    "ips":        60,
    "public_ips": 60,
    "domains":    30,
    "hashes":     None,   # hashes never expire — they identify a unique binary
    "processes":  90,
    "users":      365,
    "hosts":      365,
}


def _collect_iocs_from_rows(rows: list[dict]) -> dict[str, list[str]]:
    import time as _t
    import datetime as _dt
    _now = _t.time()
    iocs: dict[str, set[str]] = {k: set() for k in ("ips", "public_ips", "processes", "domains", "hashes", "users", "hosts")}
    for row in rows:
        # Parse row timestamp once for cutoff gating
        _row_ts_str = str(row.get("ts") or row.get("timestamp") or "")
        _row_ep: float | None = None
        if _row_ts_str:
            try:
                _row_ep = _dt.datetime.fromisoformat(_row_ts_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                _row_ep = None
        for field, target in [
            ("src_ip", "ips"), ("dst_ip", "ips"), ("ip", "ips"),
            ("process_name", "processes"), ("process", "processes"), ("child_process", "processes"),
            ("domain", "domains"), ("from_domain", "domains"),
            ("sha256", "hashes"), ("file_hash", "hashes"), ("child_hash_sha256", "hashes"),
            ("user", "users"), ("username", "users"), ("user_principal_name", "users"), ("userPrincipalName", "users"),
            ("hostname", "hosts"), ("host", "hosts"),
        ]:
            value = str(row.get(field) or "").strip()
            if not value or value.lower() in {"unknown", "none", "n/a"}:
                continue
            # Hard cutoff: drop stale IOCs when we have a timestamp to compare
            cutoff = _IOC_CUTOFF_DAYS.get(target)
            if cutoff is not None and _row_ep is not None:
                age_days = (_now - _row_ep) / 86400.0
                if age_days > cutoff:
                    continue
            iocs[target].add(value)
        dst_ip = str(row.get("dst_ip") or "").strip()
        if dst_ip and not dst_ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")):
            # Apply public-IP cutoff too
            cutoff_pub = _IOC_CUTOFF_DAYS.get("public_ips")
            if cutoff_pub is None or _row_ep is None or (_now - _row_ep) / 86400.0 <= cutoff_pub:
                iocs["public_ips"].add(dst_ip)
    return {key: sorted(values) for key, values in iocs.items()}


def _model_from_assessment(assessment: dict, raw_rows: list[dict], filename: str) -> dict:
    findings = [item for item in (assessment.get("findings") or []) if isinstance(item, dict)]
    row_by_index = {}
    for idx, row in enumerate(raw_rows):
        if not isinstance(row, dict):
            continue
        key = row.get("row_index", idx)
        row_by_index[key] = row
        row_by_index[idx] = row

    evidence: list[dict] = []
    for pos, finding in enumerate(findings, start=1):
        row = row_by_index.get(finding.get("row_index")) or {}
        sheet = str(finding.get("sheet") or row.get("sheet") or row.get("_sheet") or "").strip()
        code = f"E{pos:02d}"
        import time as _t_now
        evidence.append({
            "code": code,
            "row": row,
            "ts_human": str(row.get("ts") or row.get("timestamp") or ""),
            # Bitemporal columns (P0 Phase 0)
            "valid_time":       str(row.get("ts") or row.get("timestamp") or ""),
            "transaction_time": str(row.get("_ingested_at") or "") or __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
            "verdict": _verdict_from_finding(finding),
            "severity": str(finding.get("severity") or "medium").lower(),
            "dread": round(float(finding.get("confidence") or 0.0) * 10, 2),
            "factors": list(finding.get("factors") or []),
            "mitre": list(finding.get("mitre") or []),
            "summary": str(finding.get("title") or ""),
            "sheet": sheet,
        })

    evidence.sort(key=lambda item: (item["verdict"] != "malicious", item["severity"], item["code"]))
    iocs = _collect_iocs_from_rows(raw_rows)
    malicious_count = sum(1 for item in evidence if item.get("verdict") == "malicious")
    suspicious_count = sum(1 for item in evidence if item.get("verdict") == "suspicious")
    overall = str((assessment.get("verdict") or {}).get("final_verdict") or assessment.get("final_verdict") or assessment.get("severity") or "LOW").upper()
    pivots: list[dict] = []
    support_map: dict[str, list[str]] = {}
    for ev in evidence:
        row = ev.get("row") or {}
        for value in [row.get("src_ip"), row.get("dst_ip"), row.get("host"), row.get("hostname"), row.get("user"), row.get("user_principal_name"), row.get("userPrincipalName"), row.get("process"), row.get("process_name"), row.get("from_address")]:
            token = str(value or "").strip()
            if not token:
                continue
            support_map.setdefault(token, []).append(ev.get("code"))
    for token, refs in list(support_map.items())[:8]:
        if len(refs) < 2:
            continue
        pivots.append({"entity": token, "codes": refs[:5]})

    return {
        "evidence": evidence,
        "iocs": iocs,
        "pivots": pivots,
        "kill_chain": [],
        "claims": [],
        "attack_story": {
            "narrative": assessment.get("attack_narrative") or "",
            "start_ts": min((str((ev.get("row") or {}).get("ts") or (ev.get("row") or {}).get("timestamp") or "") for ev in evidence if (ev.get("row") or {}).get("ts") or (ev.get("row") or {}).get("timestamp")), default="—"),
            "attacker_ips": iocs.get("public_ips") or [],
            "internal_hosts": iocs.get("hosts") or [],
            "internal_users": iocs.get("users") or [],
            "c2_connections": {},
            "beacon_intervals": [],
            "event_deltas": {},
            "evidence_quality": {},
            "sorted_events": evidence,
            "data_at_risk": [],
            "duration_minutes": None,
            "phish_to": "",
            "phish_from": "",
            "phish_subject": "",
            "pivot_ev": None,
            "initiating_ev": None,
            "phishing_ev": None,
        },
        "has_pii": any(str(row.get("user_principal_name") or row.get("from_address") or row.get("to_address") or "").strip() for row in raw_rows),
        "has_c2": any(
            any(token in str(factor).lower() for token in ("c2", "beacon", "external_ip", "external_flow"))
            for item in evidence for factor in (item.get("factors") or [])
        ),
        "has_email": any((str((item.get("sheet") or "")).lower() == "email") for item in evidence),
        "has_endpoint": any((str((item.get("sheet") or "")).lower() in ("endpoint", "edr")) for item in evidence),
        "has_network": any((str((item.get("sheet") or "")).lower() in ("network", "c2")) for item in evidence),
        "has_cloud": any("cloud" in str(item.get("sheet") or "").lower() for item in evidence),
        "overall_risk": overall,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "total_count": len(raw_rows),
        "flagged_count": len([item for item in evidence if item.get("verdict") in {"malicious", "suspicious"}]),
        "threat_models": _compute_threat_models(evidence),
    }


# ---------------------------------------------------------------------------
# Threat model computation (P1-3 STRIDE, P1-4 MAESTRO)
# ---------------------------------------------------------------------------

_RFC1918_PREFIXES_ADT = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "fe80:",
)


def _compute_threat_models(evidence: list[dict]) -> dict:
    """Compute STRIDE, Diamond, MAESTRO and PASTA threat models from evidence list.

    Each evidence item has: sheet, factors, verdict, row (raw row dict), mitre, dread.
    Returns a dict compatible with the pipeline script's build_threat_models() output.
    """
    _STRIDE_LABELS = {
        "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
        "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
    }
    _FACTOR_STRIDE: dict[str, str] = {
        # Spoofing
        "phishing_subject": "S", "credential_harvest": "S", "bec_indicators": "S",
        "reply_to_mismatch": "S", "spoofed_display_name": "S",
        # Tampering
        "dropper_file_write": "T", "masquerading_extension": "T", "malicious_process": "T",
        "process_injection": "T",
        # Repudiation
        "log_clearing": "R", "audit_trail_deletion": "R",
        # Information Disclosure
        "c2_data_staging": "I", "data_exfiltration_confirmed": "I", "external_dns_query": "I",
        # Denial of Service
        "dos_pattern": "D", "flood_network": "D",
        # Elevation of Privilege
        "privilege_escalation": "E", "lateral_movement_tool": "E", "rdp_lateral_movement": "E",
        "smb_external": "E",
    }

    stride_counts: dict[str, list] = {k: [] for k in "STRIDE"}
    all_factors: set[str] = set()
    for ev in evidence:
        row = ev.get("row") or {}
        factors = list(ev.get("factors") or row.get("factors") or [])
        all_factors.update(factors)
        ident = (row.get("process") or row.get("process_name") or
                 row.get("src_ip") or row.get("from") or row.get("subject") or
                 f"row-{row.get('row_index', ev.get('code', ''))}")
        sheet = str(ev.get("sheet") or row.get("_sheet") or "")
        for f in factors:
            sc = _FACTOR_STRIDE.get(f)
            if sc:
                stride_counts[sc].append({
                    "row_index": row.get("row_index"),
                    "identifier": str(ident)[:60],
                    "sheet": sheet,
                })

    stride_summary = {}
    for code, label in _STRIDE_LABELS.items():
        items = stride_counts.get(code, [])
        status = "CONFIRMED" if len(items) >= 2 else ("SUSPECTED" if len(items) == 1 else "NOT DETECTED")
        stride_summary[code] = {"label": label, "status": status, "count": len(items), "evidence": items[:5]}

    # Diamond model — separate adversary (public) from victim (internal) IPs
    infra: list[dict] = []
    victims: list[dict] = []
    capabilities: list[dict] = []
    seen_ips: set[str] = set()
    seen_victims: set[str] = set()
    for ev in evidence:
        row = ev.get("row") or {}
        factors = list(ev.get("factors") or row.get("factors") or [])
        dst = str(row.get("dst_ip") or "").strip()
        src = str(row.get("src_ip") or "").strip()
        is_public_dst = dst and not any(dst.startswith(p) for p in _RFC1918_PREFIXES_ADT)
        if is_public_dst and dst not in seen_ips:
            seen_ips.add(dst)
            role = "C2" if any(f in factors for f in ("c2_communication", "c2_port", "external_connection")) else "unknown"
            infra.append({"ip": dst, "port": row.get("dst_port", ""), "role": role})
        target = str(row.get("to") or row.get("hostname") or row.get("computer") or "").strip()
        if target and target not in seen_victims and ev.get("verdict") in ("malicious", "suspicious"):
            seen_victims.add(target)
            status_v = "COMPROMISED" if ev.get("verdict") == "malicious" else "TARGETED"
            victims.append({"identity": target, "sheet": ev.get("sheet", ""), "status": status_v})
        proc = str(row.get("process") or row.get("process_name") or "").strip()
        if proc and any(f in factors for f in ("malicious_process", "lateral_movement_tool", "dropper_file_write")):
            soph = "MEDIUM-HIGH" if "lateral_movement_tool" in factors else "MEDIUM"
            mitre_first = (ev.get("mitre") or [""])[0]
            capabilities.append({"tool": proc, "mitre": mitre_first, "sophistication": soph})

    diamond_model = {
        "adversary": {"profile": "Unknown adversary", "confidence": "LOW", "indicators": sorted(seen_ips)[:4]},
        "infrastructure": infra[:10],
        "victims": victims[:10],
        "capabilities": capabilities[:10],
    }

    # MAESTRO stages
    _MAESTRO_MAP = [
        ("M - Mission",   ["c2_communication", "c2_data_staging", "lateral_movement"],               "Financial fraud / Ransomware / Data exfiltration"),
        ("A - Adversary", ["lateral_movement_tool", "malicious_process"],                             "Commodity tools suggest organised crime or RaaS affiliate"),
        ("E - Environment", ["process_execution", "external_connection"],                             "Windows domain environment inferred"),
        ("S - Source",    ["phishing_subject", "credential_harvest"],                                 "Spearphishing emails to known employees"),
        ("T - Transform", ["malicious_process", "dropper_file_write", "masquerading_extension"],      "Payload staging via dropper"),
        ("R - Relay",     ["c2_communication", "c2_port", "external_connection", "smb_external"],     "Encrypted C2 relay infrastructure"),
        ("O - Output",    ["c2_data_staging", "lateral_movement", "rdp_lateral_movement"],            "Data exfiltration suspected"),
    ]
    maestro_stages = []
    for stage_name, triggers, description in _MAESTRO_MAP:
        detected = any(f in all_factors for f in triggers)
        ev_factors = [f for f in triggers if f in all_factors]
        maestro_stages.append({"stage": stage_name, "detected": detected,
                                "evidence_factors": ev_factors, "description": description})

    # PASTA risk matrix (Stage 7 approximation)
    pasta_risks: list[dict] = []
    mal_count = sum(1 for ev in evidence if ev.get("verdict") == "malicious")
    has_lateral = any(f in all_factors for f in ("lateral_movement", "rdp_lateral_movement"))
    has_c2 = "c2_communication" in all_factors
    has_phish = any(f in all_factors for f in ("phishing_subject", "credential_harvest"))
    has_exfil = any(f in all_factors for f in ("c2_data_staging", "data_exfiltration_confirmed"))
    if has_lateral and has_c2:
        pasta_risks.append({"risk": "Ransomware deployment on domain", "likelihood": "HIGH", "impact": "CRITICAL", "score": 9.5, "priority": "P0"})
    if has_lateral:
        pasta_risks.append({"risk": "Full domain compromise via lateral movement", "likelihood": "HIGH", "impact": "CRITICAL", "score": 9.0, "priority": "P0"})
    if has_exfil or has_c2:
        pasta_risks.append({"risk": "PII exfiltration (GDPR breach)", "likelihood": "HIGH", "impact": "HIGH", "score": 8.0, "priority": "P0"})
    if has_phish:
        pasta_risks.append({"risk": "Credential theft enabling future access", "likelihood": "HIGH", "impact": "HIGH", "score": 7.5, "priority": "P1"})
        pasta_risks.append({"risk": "Regulatory fine (GDPR 4% global turnover)", "likelihood": "MEDIUM", "impact": "HIGH", "score": 7.0, "priority": "P1"})
    if mal_count >= 2:
        pasta_risks.append({"risk": "Business disruption / data unavailability", "likelihood": "MEDIUM", "impact": "HIGH", "score": 6.5, "priority": "P1"})

    return {
        "stride_summary": stride_summary,
        "diamond_model": diamond_model,
        "maestro_stages": maestro_stages,
        "pasta_risk_matrix": pasta_risks,
    }


# ---------------------------------------------------------------------------
# Lightweight model fallback
# ---------------------------------------------------------------------------

def _minimal_model(raw_rows: list[dict], filename: str) -> dict:
    """Build a lightweight canonical model when no pre-built model is available."""
    evidence: list[dict] = []
    iocs: dict[str, set] = {k: set() for k in
        ("ips", "public_ips", "processes", "domains", "hashes", "users", "hosts")}

    _RFC1918_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                         "127.", "::1", "fe80:")

    def _is_public(ip: str) -> bool:
        return bool(ip) and not any(ip.startswith(p) for p in _RFC1918_PREFIXES)

    for i, r in enumerate(raw_rows, start=1):
        if not isinstance(r, dict):
            continue
        verdict = str(r.get("verdict") or "unknown").lower()
        if verdict not in ("malicious", "suspicious"):
            continue
        code = r.get("_evidence_code") or f"E{i:02d}"
        evidence.append({
            "code":     code,
            "row":      r,
            "ts_human": str(r.get("ts") or r.get("timestamp") or "—"),
            # Bitemporal columns (P0 Phase 0)
            "valid_time":       str(r.get("ts") or r.get("timestamp") or "—"),
            "transaction_time": str(r.get("_ingested_at") or "") or __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
            "verdict":  verdict,
            "severity": str(r.get("severity") or "medium").lower(),
            "dread":    float(r.get("dread_score") or 0),
            "factors":  list(r.get("factors") or []),
            "mitre":    list(r.get("mitre_techniques") or []),
            "summary":  str(r.get("llm_summary") or r.get("summary") or ""),
            "sheet":    str(r.get("_sheet") or ""),
        })
        for field, target in [
            ("src_ip", "ips"), ("dst_ip", "ips"), ("c2_ip", "ips"),
            ("process_name", "processes"), ("process", "processes"),
            ("domain", "domains"), ("hash", "hashes"), ("sha256", "hashes"),
            ("user", "users"), ("username", "users"),
            ("hostname", "hosts"), ("computer", "hosts"),
        ]:
            val = str(r.get(field) or "").strip()
            if val and val not in ("?", "unknown", "—", ""):
                iocs[target].add(val)
        # Separately collect public IPs for Diamond adversary attribution (P1-1)
        for ip_field in ("src_ip", "dst_ip", "c2_ip"):
            ip_val = str(r.get(ip_field) or "").strip()
            if _is_public(ip_val):
                iocs["public_ips"].add(ip_val)

    n_mal  = sum(1 for ev in evidence if ev["verdict"] == "malicious")
    n_sus  = sum(1 for ev in evidence if ev["verdict"] == "suspicious")
    overall = ("CRITICAL" if n_mal > 2 else "HIGH" if n_mal > 0
               else "MEDIUM" if n_sus > 0 else "LOW")

    mal_codes = [ev["code"] for ev in evidence if ev["verdict"] == "malicious"]
    sus_codes = [ev["code"] for ev in evidence if ev["verdict"] == "suspicious"]
    pivot_ev   = next(
        (ev for ev in evidence
         if any("lateral" in f.lower() or "wmi" in f.lower() for f in ev.get("factors", []))),
        None,
    )
    return {
        "evidence":        evidence,
        "iocs":            {k: sorted(v) for k, v in iocs.items()},
        "pivots":          [],
        "kill_chain":      [],
        "claims": (
            [
                {"claim": "Malicious activity was observed in the dataset.", "status": "CONFIRMED",
                 "evidence_codes": mal_codes[:5], "confidence_band": "Observed"},
                {"claim": "Data exfiltration to an external attacker occurred.", "status": "UNKNOWN",
                 "evidence_codes": [], "confidence_band": "Unknown"},
                {"claim": "A persistence mechanism was installed.", "status": "UNKNOWN",
                 "evidence_codes": [], "confidence_band": "Unknown"},
            ] if n_mal > 0 else
            [{"claim": "Suspicious activity was observed in the dataset.", "status": "SUSPECTED",
              "evidence_codes": sus_codes[:5], "confidence_band": "Likely"}]
        ),
        "attack_story": {
            "narrative":        "",
            "start_ts":         "—",
            "attacker_ips":     sorted(iocs.get("public_ips") or iocs.get("ips", set())),
            "internal_hosts":   sorted(iocs.get("hosts", set())),
            "internal_users":   sorted(iocs.get("users", set())),
            "c2_connections":   {},
            "beacon_intervals": [],
            "event_deltas":     {},
            "evidence_quality": {},
            "sorted_events":    evidence,
            "data_at_risk":     [],
            "duration_minutes": None,
            "phish_to": "", "phish_from": "", "phish_subject": "",
            "pivot_ev":  pivot_ev, "initiating_ev": None, "phishing_ev": None,
        },
        "has_pii":      any("email" == (ev.get("sheet") or "").lower()
                            for ev in evidence),
        "has_c2":       any("c2" in f.lower() or "beacon" in f.lower()
                            for ev in evidence for f in ev.get("factors", [])),
        "has_email":    any("email" == (ev.get("sheet") or "").lower()
                            for ev in evidence),
        "has_endpoint": any((ev.get("sheet") or "").lower() in ("endpoint", "edr")
                            for ev in evidence),
        "has_network":  any((ev.get("sheet") or "").lower() == "network"
                            for ev in evidence),
        "overall_risk":     overall,
        "malicious_count":  n_mal,
        "suspicious_count": n_sus,
        "total_count":      len(raw_rows),
        "flagged_count":    len(evidence),
        "threat_models":    _compute_threat_models(evidence),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def csv_assessment_to_v3_payload(
    assessment: dict,
    filename: str,
    persona: str = "executive",
    model: dict | None = None,
) -> dict:
    """Convert a CSV pipeline assessment dict to a v3 executive report payload.

    Parameters
    ----------
    assessment : dict
        Assessment returned by ``poll_assessment()`` or loaded from disk.
        Expected to contain ``rows`` or ``llm_rows``.
    filename : str
        Original filename, e.g. ``Cyberstash_csv2.xlsx``.
    persona : str
        Target persona — controls evidence lookback window and recency weighting.
    model : dict | None
        Pre-built canonical model from ``_build_canonical_model(rows, filename)``.
        When omitted a lightweight model is derived from the rows.

    Returns
    -------
    dict
        Compatible with ``build_executive_report_artifact(payload)``.
    """
    from src.core.configuration.persona_windows import get_persona_window
    persona_cfg = get_persona_window(persona)
    lookback_hours: int = persona_cfg["lookback_hours"]
    recency_weight: float = persona_cfg["recency_weight"]

    raw_rows = _select_assessment_rows(assessment)
    aid      = (assessment.get("assessment_id") or assessment.get("report_id") or "")

    # Map rows to v3 format
    mapped_rows: list[dict] = [
        _map_row(row, i, filename)
        for i, row in enumerate(raw_rows, start=1)
        if isinstance(row, dict)
    ]

    if model is None:
        if assessment.get("findings"):
            model = _model_from_assessment(assessment, raw_rows, filename)
        else:
            model = _minimal_model(raw_rows, filename)

    overall = model.get("overall_risk") or "HIGH"
    n_mal   = model.get("malicious_count") or 0
    n_sus   = model.get("suspicious_count") or 0
    n_total = model.get("total_count") or len(raw_rows)
    atk     = model.get("attack_story") or {}
    ev_list = model.get("evidence") or []

    # Persona-scoped evidence window: limit visible evidence per persona's lookback
    # and apply recency weighting (P0 Phase 0 — zero schema changes).
    import time as _time
    _now = _time.time()
    _lookback_secs = lookback_hours * 3600

    def _ev_epoch(ev: dict) -> float | None:
        """Extract epoch from evidence item's ts_human or row timestamp fields."""
        ts = ev.get("ts_human") or (ev.get("row") or {}).get("ts") or (ev.get("row") or {}).get("timestamp") or ""
        ts_str = str(ts).strip()
        if not ts_str or ts_str == "—":
            return None
        try:
            from datetime import datetime, timezone as _tz
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(ts_str[:19], fmt).replace(tzinfo=_tz.utc).timestamp()
                except ValueError:
                    pass
            ep_raw = float(ts_str)
            if 1_000_000_000 < ep_raw < 9_999_999_999:
                return ep_raw
        except (ValueError, TypeError):
            pass
        return None

    # Filter evidence to persona lookback window; fall back to ALL if no timestamps
    _windowed_ev = []
    _all_ev = list(ev_list)
    for ev in _all_ev:
        ep = _ev_epoch(ev)
        if ep is None or (_now - ep) <= _lookback_secs:
            _windowed_ev.append(ev)

    # If windowing would remove everything (old dataset), use all evidence
    if not _windowed_ev:
        _windowed_ev = _all_ev

    # Sort by recency weight: higher-recency-weight personas see most-recent first
    if recency_weight > 0.5 and len(_windowed_ev) > 1:
        def _sort_key(ev: dict) -> float:
            ep = _ev_epoch(ev) or 0.0
            sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            sev_boost = sev_rank.get(ev.get("severity") or "info", 0) * 1000
            return ep + sev_boost
        _windowed_ev.sort(key=_sort_key, reverse=True)

    max_ev = persona_cfg.get("max_events", 30)
    ev_list = _windowed_ev[:max_ev]
    # Sync the windowed+capped list back into the model so _csv_model reflects persona scope
    model = dict(model)
    model["evidence"] = ev_list

    confidence = min(0.98, 0.40 + n_mal * 0.08 + n_sus * 0.02)

    # Findings list for MITRE / framework extraction
    findings = []
    for ev in ev_list:
        r = ev.get("row") or {}
        findings.append({
            "title":      (ev.get("summary")
                           or ((ev.get("factors") or ["event"])[0]
                               if ev.get("factors") else "event")),
            "severity":   ev.get("severity") or "medium",
            "confidence": ev.get("dread", 0) / 10.0 if ev.get("dread") else 0.5,
            "sheet":      ev.get("sheet") or "",
            "row_index":  int((ev.get("row") or {}).get("_row_index") or 0),
            "factors":    ev.get("factors") or [],
            "mitre":      ev.get("mitre") or [],
        })

    # Narrative (from attack story or synthesised)
    narrative = atk.get("narrative") or (
        f"Analysis identified {n_mal} confirmed malicious and {n_sus} suspicious "
        f"events out of {n_total:,} total records in {filename}."
    )

    # Attack timeline for evidence appendix timeline section
    attack_timeline = [
        {
            "ts":         (ev.get("row") or {}).get("ts") or (ev.get("row") or {}).get("timestamp"),
            "entity":     ((ev.get("row") or {}).get("hostname")
                           or (ev.get("row") or {}).get("user")
                           or (ev.get("row") or {}).get("src_ip") or ""),
            "domain":     ev.get("sheet") or "csv",
            "confidence": ev.get("verdict"),
        }
        for ev in (atk.get("sorted_events") or ev_list)[:12]
    ]

    # Build the evidence appendix before passing to enrich_canonical_report.
    # enrich_canonical_report uses setdefault so our pre-populated appendix is preserved.
    evidence_appendix = _build_appendix(mapped_rows, model, filename)

    # MITRE set for framework section extraction
    all_mitre = sorted({
        m for ev in ev_list for m in (ev.get("mitre") or [])
    })[:12]

    return {
        # ── Identity ──────────────────────────────────────────────────────
        "report_id":       aid,
        "assessment_id":   aid,
        "org":             filename,
        "tenant_name":     filename,
        "tenant_id":       filename,

        # ── Event rows (v3 format) ────────────────────────────────────────
        "rows": mapped_rows,

        # ── Findings for framework/MITRE extraction ───────────────────────
        "findings":        findings,

        # ── Verdict summary ───────────────────────────────────────────────
        "verdict": {
            "final_verdict":    overall,
            "final_confidence": round(confidence, 2),
        },

        # ── Narrative ─────────────────────────────────────────────────────
        "attack_narrative": narrative,
        "attack_timeline":  attack_timeline,

        # ── Risk quantification (business outcomes) ───────────────────────
        "risk_quantification": {
            "severity":           overall,
            "likelihood_percent": round(min(90, 20 + n_mal * 8), 1),
            "expected_loss_usd":  _RISK_LOSS.get(overall, 12_000),
            "impact_range_usd":   [0, _RISK_LOSS_MAX.get(overall, 36_000)],
            "damage_potential":   n_mal + n_sus,
            "evidence_based":     n_mal > 0,
        },

        # ── Impact metadata ───────────────────────────────────────────────
        "impact_metadata": {
            "business_criticality": {"highest": {"label": overall.capitalize()}},
            "analyst_workflow":     {},
        },

        # ── MITRE (framework section) ─────────────────────────────────────
        "mitre_techniques": all_mitre,

        # ── Pre-populated appendix ────────────────────────────────────────
        # enrich_canonical_report respects this via setdefault().
        "evidence_appendix": evidence_appendix,

        # ── Source context (provider chip + trend suppression signal) ─────
        "_source_context": {
            "type":     "csv_upload",
            "filename": filename,
            "provider": "CSV Upload",
        },

        # ── Raw canonical model — persona section builders read this ──────
        "_csv_model": model,
    }
