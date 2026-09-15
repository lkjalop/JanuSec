"""canonical_adapter.py — Unified canonical model builder.

Both the CSV pipeline (scripts/run_cyberstash_full_pipeline.py) and the cloud
path (src/reporting/executive_reporting.py) produce slightly different canonical
shapes.  This module is the single source of truth:

    build_canonical_model(rows, meta=None) -> canonical_report dict

Both paths should call this function instead of building their own shapes so
that persona renderers, scoring helpers, and tests always consume identical keys.

It also exposes:

    plain_english_narrative(canonical_report) -> str
    plain_english_findings(canonical_report) -> list[dict]

These produce audience-safe, non-technical explanations suitable for CISO
briefs, board slides, and legal holds, in addition to the technical personas.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Sentinel for missing optional deps (keeps this module importable everywhere)
# ---------------------------------------------------------------------------
try:
    from src.reporting.persona_template_packs import enrich_canonical_report as _enrich
except Exception:
    _enrich = None  # type: ignore

# ---------------------------------------------------------------------------
# Cloud / kernel source taxonomy
# ---------------------------------------------------------------------------

#: All supported source kinds and their human-readable labels + domain bucket.
SOURCE_CATALOG: Dict[str, Dict[str, str]] = {
    # Azure
    "entra_signin":          {"label": "Azure AD sign-in log",           "domain": "identity",  "provider": "Azure"},
    "entra_audit":           {"label": "Azure AD audit log",             "domain": "identity",  "provider": "Azure"},
    "defender_cloud":        {"label": "Microsoft Defender for Cloud",   "domain": "cloud",     "provider": "Azure"},
    "event_hub":             {"label": "Azure Event Hub stream",         "domain": "cloud",     "provider": "Azure"},
    "azure_activity":        {"label": "Azure Activity log",             "domain": "cloud",     "provider": "Azure"},
    "sentinel_incident":     {"label": "Microsoft Sentinel incident",    "domain": "cloud",     "provider": "Azure"},
    "nsg_flow":              {"label": "Azure NSG flow log",             "domain": "network",   "provider": "Azure"},
    "conditional_access":    {"label": "Azure Conditional Access",       "domain": "identity",  "provider": "Azure"},
    "identity_protection":   {"label": "Azure Identity Protection",      "domain": "identity",  "provider": "Azure"},
    "purview":               {"label": "Microsoft Purview",              "domain": "data",      "provider": "Azure"},
    # AWS
    "cloudtrail":            {"label": "AWS CloudTrail",                 "domain": "cloud",     "provider": "AWS"},
    "guardduty":             {"label": "AWS GuardDuty finding",          "domain": "cloud",     "provider": "AWS"},
    "vpcflow":               {"label": "AWS VPC Flow log",               "domain": "network",   "provider": "AWS"},
    "securityhub":           {"label": "AWS Security Hub finding",       "domain": "cloud",     "provider": "AWS"},
    "iam_changes":           {"label": "AWS IAM change event",           "domain": "identity",  "provider": "AWS"},
    "s3_access":             {"label": "AWS S3 access log",              "domain": "data",      "provider": "AWS"},
    "cloudwatch":            {"label": "AWS CloudWatch metric/log",      "domain": "cloud",     "provider": "AWS"},
    "config_snapshot":       {"label": "AWS Config resource snapshot",   "domain": "cloud",     "provider": "AWS"},
    # Email
    "proofpoint":            {"label": "Proofpoint TAP alert",           "domain": "email",     "provider": "Proofpoint"},
    "microsoft_graph_email": {"label": "Microsoft Graph mail event",     "domain": "email",     "provider": "Microsoft"},
    "mimecast":              {"label": "Mimecast alert",                 "domain": "email",     "provider": "Mimecast"},
    "abnormal":              {"label": "Abnormal Security alert",        "domain": "email",     "provider": "Abnormal"},
    "cofense":               {"label": "Cofense Vision report",          "domain": "email",     "provider": "Cofense"},
    # Endpoint / kernel
    "sysmon":                {"label": "Windows Sysmon event",           "domain": "endpoint",  "provider": "Microsoft"},
    "crowdstrike":           {"label": "CrowdStrike detection",          "domain": "endpoint",  "provider": "CrowdStrike"},
    "ebpf":                  {"label": "Linux eBPF syscall trace",       "domain": "endpoint",  "provider": "kernel"},
    "etw":                   {"label": "Windows ETW trace",              "domain": "endpoint",  "provider": "Microsoft"},
    "wef":                   {"label": "Windows Event Forwarding",       "domain": "endpoint",  "provider": "Microsoft"},
    # Network / packet
    "suricata":              {"label": "Suricata IDS alert",             "domain": "network",   "provider": "Suricata"},
    "zeek":                  {"label": "Zeek network log",               "domain": "network",   "provider": "Zeek"},
    "netflow":               {"label": "NetFlow record",                 "domain": "network",   "provider": "network"},
    # SSE / proxy
    "netskope":              {"label": "Netskope event",                 "domain": "cloud",     "provider": "Netskope"},
    "zscaler":               {"label": "Zscaler ZIA/ZPA log",            "domain": "cloud",     "provider": "Zscaler"},
    # SIEM forwarding
    "splunk":                {"label": "Splunk forwarded event",         "domain": "siem",      "provider": "Splunk"},
    "elastic":               {"label": "Elastic ECS event",             "domain": "siem",      "provider": "Elastic"},
    # Vuln / posture
    "qualys":                {"label": "Qualys vulnerability finding",   "domain": "vuln",      "provider": "Qualys"},
    "tenable":               {"label": "Tenable finding",               "domain": "vuln",      "provider": "Tenable"},
    # Generic
    "csv":                   {"label": "Uploaded log rows",              "domain": "generic",   "provider": "manual"},
}

# Kernel / host telemetry sources that support deep forensic collection
KERNEL_SOURCES = {"sysmon", "ebpf", "etw", "wef", "crowdstrike"}

# ---------------------------------------------------------------------------
# Non-technical severity vocabulary
# ---------------------------------------------------------------------------

SEVERITY_PLAIN: Dict[str, str] = {
    "critical": "a serious security problem that needs your attention today",
    "high":     "a strong signal of suspicious activity that warrants review",
    "medium":   "an unusual pattern your team should look into",
    "low":      "a minor signal that may be background noise or benign",
    "info":     "an informational observation with no immediate action required",
}

ACTION_PLAIN: Dict[str, str] = {
    "identity":  "Confirm whether the affected account is still in the right hands and whether any access changes should be reversed.",
    "cloud":     "Check whether any cloud configuration, permissions, or resources were changed unexpectedly.",
    "endpoint":  "Verify whether the affected device has been compromised and consider isolating it for review.",
    "network":   "Confirm whether the observed traffic was expected and whether any data left the environment.",
    "email":     "Verify whether the email campaign reached real users and whether any credentials or links were acted on.",
    "data":      "Confirm whether sensitive data was accessed or moved, and whether any protective controls need to be applied.",
    "vuln":      "Review whether the identified software weakness is exposed in your environment and prioritise patching.",
    "siem":      "Investigate via your SIEM or alert queue to determine scope and assign an owner.",
    "cloud_id":  "Check both the cloud account and the related identity simultaneously — activity spanning both domains needs a unified owner.",
    "generic":   "Your security team will review and contact you if any action is required on your part.",
}

# ---------------------------------------------------------------------------
# Canonical field schema
# ---------------------------------------------------------------------------

CANONICAL_FIELDS = (
    "source", "source_kind", "tenant_id", "provider",
    "event_type", "event_ts", "ts",
    "user", "actor", "ip", "src_ip", "dst_ip",
    "resource", "action", "domain",
    "process", "process_name", "file_hash", "sha256",
    "factors", "risk_signals", "confidence", "severity",
    "mitre", "stride", "dread", "diamond", "atlas", "pasta",
    "review_state", "triage_status", "label",
    "correlation_keys",
    "raw", "raw_ref",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_ts(row: Dict[str, Any]) -> Optional[float]:
    for key in ("ts", "event_ts", "createdDateTime", "activityDateTime",
                "eventTimestamp", "time", "@timestamp", "created_at"):
        value = row.get(key)
        if value is None:
            continue
        try:
            if isinstance(value, (int, float)):
                return float(value)
            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text).timestamp()
        except Exception:
            continue
    return None


def _source_info(source_kind: Any) -> Dict[str, str]:
    key = str(source_kind or "").strip().lower()
    # partial match fallback
    for catalog_key, meta in SOURCE_CATALOG.items():
        if catalog_key in key or key in catalog_key:
            return meta
    return {"label": key or "unknown source", "domain": "generic", "provider": "unknown"}


def _severity_from_confidence(conf: float) -> str:
    if conf >= 0.90:
        return "critical"
    if conf >= 0.75:
        return "high"
    if conf >= 0.55:
        return "medium"
    if conf >= 0.35:
        return "low"
    return "info"


def _domain_for_rows(rows: List[Dict[str, Any]]) -> str:
    """Determine the primary domain from the row mix."""
    counts: Dict[str, int] = {}
    for row in rows:
        info = _source_info(row.get("source_kind") or row.get("source"))
        d = info["domain"]
        counts[d] = counts.get(d, 0) + 1
    if not counts:
        return "generic"
    # identity + cloud together → special combined label
    has_id = counts.get("identity", 0) > 0
    has_cloud = counts.get("cloud", 0) > 0
    if has_id and has_cloud:
        return "cloud_id"
    return max(counts, key=lambda k: counts[k])


def _pivot_entities(rows: List[Dict[str, Any]]) -> List[str]:
    """Extract high-signal pivot values (users, IPs, resources) that appear in multiple rows."""
    from collections import Counter
    counter: Counter = Counter()
    for row in rows:
        for field in ("user", "actor", "ip", "src_ip", "resource", "domain", "process"):
            val = str(row.get(field) or "").strip()
            if val and val.lower() not in ("none", "null", "unknown", ""):
                counter[val] += 1
    return [entity for entity, count in counter.most_common(10) if count > 1]


def _attack_story_from_rows(rows: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build an attack story dict from raw rows and findings."""
    timeline = sorted(
        [row for row in rows if _row_ts(row) is not None],
        key=lambda r: _row_ts(r) or 0,
    )
    phases = []
    seen_sources: set = set()
    for row in timeline[:20]:
        src = str(row.get("source_kind") or row.get("source") or "")
        if src in seen_sources:
            continue
        seen_sources.add(src)
        info = _source_info(src)
        phases.append({
            "phase": info["domain"],
            "source": info["label"],
            "ts": _row_ts(row),
            "actor": row.get("user") or row.get("actor"),
            "action": row.get("action") or row.get("event_type"),
            "resource": row.get("resource") or row.get("domain"),
        })

    top_finding = findings[0] if findings else {}
    return {
        "phases": phases,
        "initial_access": phases[0] if phases else {},
        "lateral_movement": [p for p in phases if p.get("phase") in ("endpoint", "network")],
        "impact": phases[-1] if phases else {},
        "top_title": str(top_finding.get("title") or "Unclassified activity"),
        "top_confidence": float(top_finding.get("confidence") or 0.0),
        "top_mitre": (top_finding.get("mitre") or [])[:5],
    }


def _claim_register_from_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    claims = []
    for finding in findings[:8]:
        confidence = float(finding.get("confidence") or 0.0)
        status = "confirmed" if confidence >= 0.8 else ("likely" if confidence >= 0.6 else "unverified")
        claims.append({
            "statement": str(finding.get("title") or ""),
            "status": status,
            "confidence": confidence,
            "evidence_refs": (finding.get("evidence") or [])[:4],
            "mitre": (finding.get("mitre") or [])[:3],
        })
    return claims


def _shared_pivots_from_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from collections import defaultdict, Counter
    pivot_sources: Dict[str, list] = defaultdict(list)
    for row in rows:
        for field in ("user", "actor", "ip", "src_ip", "resource", "domain"):
            val = str(row.get(field) or "").strip()
            if val and val.lower() not in ("none", "null", "unknown", ""):
                src = str(row.get("source_kind") or row.get("source") or "")
                pivot_sources[val].append(src)
    pivots = []
    for pivot, sources in pivot_sources.items():
        support = len(set(sources))
        if support < 2:
            continue
        pivots.append({
            "pivot": pivot,
            "support_count": len(sources),
            "unique_sources": support,
            "sources": list(set(sources)),
            "type": "entity",
        })
    pivots.sort(key=lambda p: -p["support_count"])
    return pivots[:15]


def _evidence_appendix_from_rows(rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Build the evidence_appendix block from normalized rows."""
    source_evidence_rows = []
    for idx, row in enumerate(rows, start=1):
        info = _source_info(row.get("source_kind") or row.get("source"))
        source_evidence_rows.append({
            "index": idx,
            "_citation": f"E{idx}",
            "source_kind": row.get("source_kind") or row.get("source"),
            "source_label": info["label"],
            "provider": info["provider"],
            "domain": info["domain"],
            "user": row.get("user") or row.get("actor"),
            "ip": row.get("ip") or row.get("src_ip"),
            "resource": row.get("resource"),
            "action": row.get("action") or row.get("event_type"),
            "ts": _row_ts(row),
            "confidence": row.get("confidence"),
            "severity": row.get("severity"),
            "factors": (row.get("factors") or [])[:8],
            "business_criticality": row.get("business_criticality") or {},
            "raw_ref": row.get("raw_ref") or row.get("fingerprint"),
        })

    shared_pivots = _shared_pivots_from_rows(rows)
    domains = sorted({r["domain"] for r in source_evidence_rows if r.get("domain")})
    sources = sorted({r["source_kind"] for r in source_evidence_rows if r.get("source_kind")})

    # Focus cluster = highest correlated subset
    confidences = [float(r.get("confidence") or 0.0) for r in rows]
    avg_conf = (sum(confidences) / len(confidences)) if confidences else 0.0
    focus_cluster = {
        "score": round(avg_conf, 3),
        "sources": sources,
        "domains": domains,
        "component_count": len(set(r.get("source_kind", "") for r in rows)),
    }

    return {
        "source_evidence_rows": source_evidence_rows,
        "shared_pivots": shared_pivots,
        "focus_cluster": focus_cluster,
        "domains": domains,
        "sources": sources,
        "tenant": meta.get("tenant"),
        "generated_at": time.time(),
    }


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_canonical_model(
    rows: List[Dict[str, Any]],
    findings: Optional[List[Dict[str, Any]]] = None,
    meta: Optional[Dict[str, Any]] = None,
    framework_mappings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build a canonical report dict that every persona renderer can consume.

    Parameters
    ----------
    rows:
        Normalized event rows from any connector.  Each row must carry at least
        ``source_kind`` (or ``source``), and ideally ``ts``, ``user``, ``ip``,
        ``resource``, ``action``, ``confidence``, ``factors``, ``mitre``.
    findings:
        Pre-scored findings list.  If not provided, a basic findings list is
        derived from the ``rows`` that have ``confidence >= 0.5``.
    meta:
        Extra context: ``tenant``, ``org``, ``report_id``, ``timeframe``, etc.
    framework_mappings:
        Pre-collected MITRE/STRIDE/DREAD framework mappings.

    Returns
    -------
    dict
        Canonical report ready for ``generate_persona_view()`` and
        ``enrich_canonical_report()``.
    """
    meta = meta or {}
    rows = [r for r in rows if isinstance(r, dict)]

    # Derive findings if not supplied
    if findings is None:
        findings = []
        for row in rows:
            conf = float(row.get("confidence") or 0.0)
            if conf < 0.5:
                continue
            findings.append({
                "title": str(row.get("action") or row.get("event_type") or "Security event"),
                "source_kind": row.get("source_kind") or row.get("source"),
                "severity": row.get("severity") or _severity_from_confidence(conf),
                "confidence": conf,
                "entity": row.get("user") or row.get("actor") or row.get("ip"),
                "evidence": [row.get("raw_ref") or row.get("fingerprint")],
                "mitre": row.get("mitre") or [],
                "stride": row.get("stride") or [],
                "dread": row.get("dread") or {},
                "diamond": row.get("diamond") or {},
                "review_state": row.get("review_state") or row.get("label") or "unknown",
            })
    findings = sorted(findings, key=lambda f: -(float(f.get("confidence") or 0.0)))

    evidence_appendix = _evidence_appendix_from_rows(rows, meta)
    shared_pivots = evidence_appendix["shared_pivots"]
    attack_story = _attack_story_from_rows(rows, findings)
    claim_register = _claim_register_from_findings(findings)

    # Collect all framework mappings from rows + supplied list
    all_mappings: List[Dict[str, Any]] = list(framework_mappings or [])
    for row in rows:
        for mitre_id in (row.get("mitre") or []):
            all_mappings.append({"framework": "mitre", "technique": mitre_id})
        for stride_cat in (row.get("stride") or row.get("stride_heuristics") or []):
            all_mappings.append({"framework": "stride", "value": stride_cat})
        dread = row.get("dread")
        if isinstance(dread, dict) and dread:
            all_mappings.append({"framework": "dread", **dread})

    provider = meta.get("provider") or _infer_provider(rows)
    ts_now = time.time()

    report: Dict[str, Any] = {
        # Identity
        "report_id": meta.get("report_id") or f"canonical-{int(ts_now)}",
        "assessment_id": meta.get("assessment_id"),
        "tenant_id": meta.get("tenant") or meta.get("tenant_id"),
        "org": meta.get("org") or meta.get("tenant"),
        "tenant_name": meta.get("tenant_name") or meta.get("tenant"),
        "provider": provider,
        "generated_at": ts_now,
        "timeframe": meta.get("timeframe") or "24h",
        # Core data
        "rows": rows,
        "findings": findings,
        "framework_mappings": all_mappings,
        "shared_pivots": shared_pivots,
        "claim_register": claim_register,
        # Story
        "attack_story": attack_story,
        "attack_timeline": attack_story.get("phases") or [],
        # Appendix
        "evidence_appendix": evidence_appendix,
        # Workflow
        "impact_metadata": {
            "analyst_workflow": meta.get("analyst_workflow") or {},
            "business_context": meta.get("business_context") or {},
        },
        # Tier metadata (for tiered triage views)
        "tier_metadata": meta.get("tier_metadata") or {},
        # QA
        "qa_review": meta.get("qa_review") or {},
        "report_regeneration": meta.get("report_regeneration") or {},
    }

    # Optionally enrich with persona template pack
    if _enrich is not None:
        try:
            report = _enrich(report)
        except Exception:
            pass

    return report


def _infer_provider(rows: List[Dict[str, Any]]) -> str:
    """Guess the primary cloud provider from source_kind tokens."""
    text = " ".join(str(r.get("source_kind") or r.get("source") or "") for r in rows).lower()
    if any(t in text for t in ("azure", "entra", "defender", "sentinel", "nsg")):
        if any(t in text for t in ("aws", "guardduty", "cloudtrail", "vpc")):
            return "Hybrid / multi-cloud"
        return "Azure"
    if any(t in text for t in ("aws", "guardduty", "cloudtrail", "vpc", "securityhub")):
        return "AWS"
    if any(t in text for t in ("gcp", "google", "bigquery", "pubsub")):
        return "GCP"
    return "Cloud"


# ---------------------------------------------------------------------------
# Non-technical narrative  (audience: board / CISO / legal)
# ---------------------------------------------------------------------------

def plain_english_findings(
    canonical_report: Dict[str, Any],
    max_findings: int = 5,
) -> List[Dict[str, Any]]:
    """Return audience-safe, non-technical explanations for the top findings.

    Each item contains:
        plain_title     — one-sentence summary without jargon
        what_happened   — two-sentence narrative any business stakeholder can follow
        why_it_matters  — business / operational consequence
        what_to_do      — single concrete owner-action
        severity_plain  — plain-language severity label
        severity        — technical severity string
        confidence_pct  — integer 0-100
    """
    findings = [f for f in (canonical_report.get("findings") or []) if isinstance(f, dict)]
    rows = canonical_report.get("rows") or []
    provider = canonical_report.get("provider") or "cloud"
    domain = _domain_for_rows(rows)

    out: List[Dict[str, Any]] = []
    seen_titles: set = set()

    for finding in findings[:max_findings * 2]:
        title = str(finding.get("title") or "Security event").strip()
        if title in seen_titles:
            continue
        seen_titles.add(title)

        conf = float(finding.get("confidence") or 0.0)
        sev = str(finding.get("severity") or _severity_from_confidence(conf)).lower()
        entity = finding.get("entity") or ""
        source = str(finding.get("source_kind") or "")
        source_label = _source_info(source).get("label") or source or "your environment"

        plain_title, what_happened, why_it_matters = _narrative_for_finding(
            title, entity, source_label, provider, domain, conf
        )

        out.append({
            "plain_title": plain_title,
            "what_happened": what_happened,
            "why_it_matters": why_it_matters,
            "what_to_do": ACTION_PLAIN.get(domain, ACTION_PLAIN["generic"]),
            "severity_plain": SEVERITY_PLAIN.get(sev, sev),
            "severity": sev,
            "confidence_pct": min(100, int(round(conf * 100))),
            "technical_title": title,
            "evidence_refs": (finding.get("evidence") or [])[:3],
            "mitre": (finding.get("mitre") or [])[:4],
        })

        if len(out) >= max_findings:
            break

    return out


def _llm_narrative(canonical_report: Dict[str, Any]) -> str | None:
    """Attempt to generate a narrative using the LLM client.

    Returns None when the LLM client is unavailable or produces a too-short result.
    Falls back gracefully — callers should use the template path when None is returned.
    """
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT
        client = DEFAULT_CLIENT
    except Exception:
        client = None
    if not client:
        return None

    findings_plain = plain_english_findings(canonical_report, max_findings=3)
    rows = canonical_report.get("rows") or []
    source_count = len({
        r.get("source_kind") or r.get("source") for r in rows if r.get("source_kind") or r.get("source")
    })
    mitre_tags: list = []
    for f in findings_plain:
        mitre_tags.extend(f.get("mitre") or [])
    mitre_tags = list(dict.fromkeys(mitre_tags))[:4]

    rq = canonical_report.get("risk_quantification") or {}
    expected_loss = rq.get("expected_loss_usd")
    severity = findings_plain[0]["severity_plain"] if findings_plain else (rq.get("severity") or "unknown")

    prompt_lines = [
        "Write a 3-paragraph non-technical security incident brief for a board/CISO audience.",
        "Paragraph 1: What happened — plain facts, no jargon, mention affected systems or users.",
        "Paragraph 2: Business risk and potential financial or operational impact.",
        "Paragraph 3: What the security team is doing next and what (if anything) the reader needs to do.",
        "",
        "TECHNICAL FINDINGS:",
    ]
    for f in findings_plain:
        prompt_lines.append(f"- {f['plain_title']}: {f['what_happened']}")
    prompt_lines += [
        f"SEVERITY: {severity}",
        f"CONFIDENCE: {findings_plain[0]['confidence_pct'] if findings_plain else 'N/A'}%",
        f"MITRE TECHNIQUES: {', '.join(mitre_tags) or 'none identified'}",
        f"DATA SOURCES: {source_count}",
    ]
    if expected_loss:
        prompt_lines.append(f"ESTIMATED FINANCIAL EXPOSURE: ${expected_loss:,}")
    prompt_lines += [
        "",
        "Respond with exactly 3 paragraphs separated by blank lines. Plain English only. No bullet points.",
    ]
    prompt = "\n".join(prompt_lines)
    try:
        result = client.generate(prompt, model='gpt-4o-mini', max_tokens=500)
        if isinstance(result, dict):
            text = result.get('text') or result.get('content') or ''
        else:
            text = str(result or '')
        text = text.strip()
        if text and len(text) > 120:
            return text
    except Exception:
        pass
    return None


def plain_english_narrative(canonical_report: Dict[str, Any]) -> str:
    """Generate a 3-paragraph non-technical executive narrative from a canonical report.

    Paragraph 1 — What happened (plain facts, no jargon).
    Paragraph 2 — Why it matters (business risk, not threat-model language).
    Paragraph 3 — What happens next (clear owner / outcome, not a tech runbook).

    Attempts an LLM-driven narrative first; falls back to deterministic templates when
    the LLM client is unavailable or returns an insufficient response.
    """
    # LLM-first path — richer, adaptive prose when a model is available
    llm_text = _llm_narrative(canonical_report)
    if llm_text:
        return llm_text

    findings_plain = plain_english_findings(canonical_report, max_findings=3)
    rows = canonical_report.get("rows") or []
    provider = canonical_report.get("provider") or "cloud"
    domain = _domain_for_rows(rows)
    tenant = (
        canonical_report.get("tenant_name")
        or canonical_report.get("org")
        or canonical_report.get("tenant_id")
        or "the organisation"
    )
    pivot_entities = _pivot_entities(rows)
    shared_pivots = canonical_report.get("shared_pivots") or []
    top_pivot = shared_pivots[0].get("pivot") if shared_pivots else (pivot_entities[0] if pivot_entities else None)
    source_count = len({
        r.get("source_kind") or r.get("source") for r in rows if r.get("source_kind") or r.get("source")
    })

    # Para 1 — what happened
    if findings_plain:
        top = findings_plain[0]
        p1 = (
            f"Our security monitoring detected {top['what_happened']}  "
            f"The activity was identified across {source_count} separate data source{'s' if source_count != 1 else ''}"
            + (f", with the same {top_pivot!r} appearing in multiple logs." if top_pivot else ".")
        )
    else:
        p1 = (
            f"Our security monitoring identified unusual activity in {provider} "
            f"across {source_count} data source{'s' if source_count != 1 else ''}."
        )

    # Para 2 — why it matters
    matter = ACTION_PLAIN.get(domain, ACTION_PLAIN["generic"])
    if findings_plain:
        top = findings_plain[0]
        p2 = (
            f"This is {top['severity_plain']}.  "
            f"{top['why_it_matters']}  "
            f"Our confidence in this assessment is {top['confidence_pct']}%."
        )
    else:
        p2 = (
            f"The security team has classified this as a situation that warrants review.  "
            f"{matter}"
        )

    # Para 3 — what happens next
    workflow = (canonical_report.get("impact_metadata") or {}).get("analyst_workflow") or {}
    if workflow.get("user_contacted"):
        p3 = "The relevant account owner has already been contacted. No action is required from you at this time unless you are contacted directly by the security team."
    elif workflow.get("change_ticket_found"):
        p3 = "A change ticket has been located, which may explain the observed activity. The security team is validating the approval trail and will update you with findings."
    else:
        p3 = (
            "The security team is investigating and will provide an update within the agreed SLA window.  "
            "If you use the affected systems, please do not change your password or take other protective steps until asked — "
            "doing so before the team is ready may hinder the investigation."
        )

    return "\n\n".join([p1, p2, p3])


def _narrative_for_finding(
    title: str,
    entity: str,
    source_label: str,
    provider: str,
    domain: str,
    confidence: float,
) -> tuple:
    """Return (plain_title, what_happened, why_it_matters) for a single finding."""
    lower = title.lower()
    entity_str = f"the account {entity!r}" if entity else "an account"
    conf_word = "strongly" if confidence >= 0.75 else "possibly"

    if any(t in lower for t in ("sign-in", "signin", "login", "authentication")):
        return (
            "Unusual login activity was detected",
            f"Someone logged in using {entity_str} in a way that does not match the normal pattern, recorded in {source_label}.",
            f"This {conf_word} indicates that {entity_str} may have been accessed by an unauthorised person.",
        )
    if any(t in lower for t in ("role", "privilege", "admin", "assume role", "policy")):
        return (
            "Administrative access was changed",
            f"{entity_str} or a related account was granted or used elevated permissions in {provider}, captured in {source_label}.",
            f"Unauthorised administrative access could allow an attacker to control or disrupt {provider} systems.",
        )
    if any(t in lower for t in ("secret", "vault", "key", "credential")):
        return (
            "Sensitive credentials or secrets were accessed",
            f"Protected configuration secrets or access keys were read from {provider} storage, as seen in {source_label}.",
            f"If the access was not authorised, the affected secrets may need to be rotated to prevent further misuse.",
        )
    if any(t in lower for t in ("bucket", "s3", "storage", "blob", "publicaccess")):
        return (
            "Cloud storage settings were changed",
            f"The permissions or configuration of a cloud storage container were modified in {provider}, observed in {source_label}.",
            f"Storage misconfigurations can expose files to unintended audiences or enable data to leave the organisation.",
        )
    if any(t in lower for t in ("exfil", "egress", "flow", "transfer", "upload", "export")):
        return (
            "Unusual data movement was observed",
            f"Files or network traffic were transferred in an unexpected direction from {provider}, seen in {source_label}.",
            f"Unexpected data movement may indicate that information left the organisation without authorisation.",
        )
    if any(t in lower for t in ("guardduty", "defender", "security hub", "securityhub")):
        return (
            f"A {provider} security alert was raised",
            f"The built-in security tools in {provider} flagged suspicious behaviour involving {entity_str}, via {source_label}.",
            f"Provider security tools have higher accuracy for their platform, so this signal should be treated as reliable.",
        )
    if any(t in lower for t in ("phish", "malware", "attachment", "click", "url")):
        return (
            "A suspicious email or link was detected",
            f"A potentially malicious email or link was identified involving {entity_str}, via {source_label}.",
            f"If the link or attachment was opened, credentials or devices may have been compromised.",
        )
    # Generic fallback
    return (
        f"Suspicious activity was detected in {provider}",
        f"An unusual security event involving {entity_str} was identified in {source_label}.",
        f"The security team is assessing whether this represents a genuine threat and will take appropriate action.",
    )


__all__ = [
    "build_canonical_model",
    "plain_english_findings",
    "plain_english_narrative",
    "SOURCE_CATALOG",
    "KERNEL_SOURCES",
]
