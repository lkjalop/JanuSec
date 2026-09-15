"""Seed a realistic GRC / Control-Assurance demo assessment to disk.

Why this exists
---------------
Every existing seeder populates the OLD graph surface (GLOBAL_HOPGRAPH). The GRC
pivot — DREAD, nonconformities, custody-hashed evidence, the ISO 19011/27035/27001
reports and the printable audit report — is only ever populated by a full live
ingest (Ollama + telemetry upload + async worker). That means the differentiator
has no demo path: a recruiter or buyer cannot see it without running the whole
pipeline.

This script builds a realistic multi-incident ``audit_pack`` from canned clusters
(the same ``build_audit_pack`` the worker uses — no LLM required), wraps it as an
assessment, and writes it to ``data/assessments/`` so a running server serves it
via the disk-aware loader. After running, open:

    /assessments.html?aid=demo-vesper            (the two-surface landing)
    /api/v1/assessments/demo-vesper/report.html  (printable ISO audit report)
    /api/v1/assessments/demo-vesper/audit-pack.html
    /api/v1/assessments/demo-vesper/report/iso27035   (+ iso27001, iso19011 as JSON)

Usage:  python scripts/seed_grc_demo.py [--id demo-vesper]

Deterministic: no Date.now/random; the transaction_time is fixed so re-running is
idempotent and the demo reads identically every time.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))

# Fixed so the seed is reproducible and the demo never drifts.
_TT = "2026-07-07T00:00:00+00:00"

# Three incidents spanning the value story: a confirmed multi-stage breach (the
# flagship), a confirmed identity/cloud breach, and a recon-only suspected event
# (shows the platform does NOT cry breach on everything).
_CLUSTERS = [
    {
        "cluster_id": "demo-vesper-01",
        "final_verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "shared_users": ["martin.chen"],
        "shared_hosts": ["ws-martin-01", "dc-01", "fileserv-03", "sql-prod-02"],
        "primary_actor": "martin.chen",
        "factor_tags": [
            "oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
            "dcsync_credential_access", "exfil:cumulative_bytes_anomaly",
        ],
        "time_window": {"start": 1776087462.0, "end": 1777408963.0, "span_seconds": 1321501.0},
        "_llm_evidence_refs": [12, 47, 103, 288, 941],
    },
    {
        "cluster_id": "demo-vesper-02",
        "final_verdict": "LIKELY_BREACH",
        "severity": "high",
        "shared_users": ["priya.nair"],
        "shared_hosts": ["ws-priya-07"],
        "primary_actor": "priya.nair",
        "factor_tags": [
            "mfa_fatigue", "aitm_session", "iam:oauth_consent_excessive_scope",
            "exfil:sharepoint_mass_download",
        ],
        "time_window": {"start": 1776520000.0, "end": 1776690000.0, "span_seconds": 170000.0},
        "_llm_evidence_refs": [55, 61, 77],
    },
    {
        "cluster_id": "demo-vesper-03",
        "final_verdict": "SUSPECTED_BREACH",
        "severity": "medium",
        "shared_users": ["svc-backup"],
        "shared_hosts": ["ws-ops-11"],
        "primary_actor": "svc-backup",
        "factor_tags": ["ad_recon_discovery"],
        "time_window": {"start": 1776600000.0, "end": 1776603600.0, "span_seconds": 3600.0},
        "_llm_evidence_refs": [214],
    },
]


# Synthetic raw events behind the cited evidence-row indices, so the claim->evidence
# drill-down (/rows/{i}) resolves to a real event + custody SHA-256 in the demo — the
# flagship "every claim is traceable to immutable evidence" story, without a live ingest.
_EVIDENCE_ROWS = [
    # incident 1 — martin.chen (oauth -> kerberoast -> wmi -> dcsync -> exfil)
    {"row_index": 12, "timestamp": "2026-04-13T13:37:02Z", "_source": "AzureAD-SignInLogs",
     "_source_type": "iam", "actor": "martin.chen", "action": "oauth_consent_grant",
     "application": "MailSync Pro", "scopes": ["Mail.ReadWrite", "offline_access"],
     "client_ip": "185.220.101.44", "result": "success"},
    {"row_index": 47, "timestamp": "2026-04-15T02:11:44Z", "_source": "WindowsSecurity-4769",
     "_source_type": "endpoint", "host": "dc-01", "actor": "martin.chen", "event_id": 4769,
     "action": "kerberos_service_ticket", "service_name": "MSSQLSvc/sql-prod-02",
     "ticket_encryption": "0x17 (RC4-HMAC)"},
    {"row_index": 103, "timestamp": "2026-04-18T09:04:12Z", "_source": "Sysmon-1",
     "_source_type": "endpoint", "host": "ws-martin-01", "target_host": "fileserv-03",
     "actor": "martin.chen", "event_id": 1, "action": "wmi_process_create",
     "process": "wmic.exe", "command_line": "wmic /node:fileserv-03 process call create"},
    {"row_index": 288, "timestamp": "2026-04-22T18:52:30Z", "_source": "WindowsSecurity-4662",
     "_source_type": "endpoint", "host": "dc-01", "actor": "martin.chen", "event_id": 4662,
     "action": "dcsync_replication", "properties": "DS-Replication-Get-Changes-All",
     "object": "DC=corp,DC=local"},
    {"row_index": 941, "timestamp": "2026-04-28T20:42:19Z", "_source": "Zscaler-Web",
     "_source_type": "network", "host": "sql-prod-02", "actor": "martin.chen",
     "action": "data_transfer", "bytes_out": 48210334176, "destination": "mega.nz",
     "category": "cloud_storage"},
    # incident 2 — priya.nair (mfa fatigue -> aitm -> mass download)
    {"row_index": 55, "timestamp": "2026-04-18T22:03:10Z", "_source": "AzureAD-SignInLogs",
     "_source_type": "iam", "actor": "priya.nair", "action": "mfa_challenge",
     "mfa_result": "14 denials then approved", "prompt_count": 14, "client_ip": "45.155.205.99"},
    {"row_index": 61, "timestamp": "2026-04-18T22:19:55Z", "_source": "AzureAD-SignInLogs",
     "_source_type": "iam", "actor": "priya.nair", "action": "sign_in",
     "session_anomaly": "impossible_travel", "client_ip": "45.155.205.99", "device": "unmanaged"},
    {"row_index": 77, "timestamp": "2026-04-19T01:40:07Z", "_source": "O365-SharePoint",
     "_source_type": "saas", "actor": "priya.nair", "action": "mass_download",
     "file_count": 1284, "site": "Finance-Confidential"},
    # incident 3 — svc-backup (recon only, suspected)
    {"row_index": 214, "timestamp": "2026-04-19T03:12:44Z", "_source": "WindowsSecurity-4661",
     "_source_type": "endpoint", "host": "ws-ops-11", "actor": "svc-backup", "event_id": 4661,
     "action": "ad_enumeration", "tool": "BloodHound collector", "query": "GetDomainUser"},
]


def build_pack():
    from src.core.grc.nonconformity import build_audit_pack
    return build_audit_pack(_CLUSTERS, transaction_time=_TT)


# A committed, self-contained rendering of the demo report. GitHub shows .html as
# source (not rendered), so the zero-setup "click and see" path is GitHub Pages
# served from /docs -> docs/demo/index.html becomes .../<repo>/demo/.
_STATIC_DEFAULT = os.path.join("docs", "demo", "index.html")
_DEMO_BANNER = (
    '<div style="background:#0f172a;color:#e2e8f0;'
    'font:13px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;'
    'padding:10px 16px;text-align:center;border-bottom:3px solid #059669">'
    'Sample report generated by <strong>JanuSec</strong> from the VESPER simulated '
    'dataset &mdash; grounded (no hallucinated entities/MITRE), custody-hashed '
    'evidence, ISO-native. Synthetic data; no real organisation.</div>'
)


def render_static(path: str = _STATIC_DEFAULT, assessment_id: str = "demo-vesper") -> str:
    """Render the demo audit report to a committed, self-contained HTML file."""
    from src.core.grc.report_templates import render_audit_report_html

    html = render_audit_report_html(build_pack(), assessment_id)
    # Inject the demo banner without forking the shared renderer.
    html = html.replace("<body>", "<body>" + _DEMO_BANNER, 1)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    external = "http://" in html or "https://" in html or "src=" in html
    print(f"wrote static report -> {path} ({len(html)} bytes, "
          f"{'has external refs!' if external else 'self-contained'})")
    return path


def seed(assessment_id: str = "demo-vesper") -> str:
    from src.api.deep_analyze.persistence import _write_assessment_index

    base = os.getenv("SESSION_PERSIST_DIR") or os.path.join(os.getcwd(), "data", "assessments")
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, f"{assessment_id}.json")

    pack = build_pack()
    assessment = {
        "assessment_id": assessment_id,
        "org": "default",
        "status": "complete",
        "audit_pack": pack,
        "evidence_rows": _EVIDENCE_ROWS,   # backs the /rows/{i} claim->evidence drill-down
        "persisted_path": path,
        "demo_seed": True,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(assessment, fh, ensure_ascii=False, indent=2)
    try:
        _write_assessment_index(assessment_id, path)
    except Exception:
        pass  # index is an optimisation; the os.walk fallback still finds the file

    findings = pack.get("findings", [])
    print(f"seeded {assessment_id}: {len(findings)} finding(s) -> {path}")
    for f in findings:
        d = f.get("dread") or {}
        print(f"  - {f.get('actor')}: {f.get('verdict')} "
              f"(DREAD {d.get('overall_score')}/{d.get('overall_level')})")
    print("\nopen:")
    print(f"  /assessments.html?aid={assessment_id}")
    print(f"  /api/v1/assessments/{assessment_id}/report.html")
    print(f"  /api/v1/assessments/{assessment_id}/audit-pack.html")
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", default="demo-vesper")
    ap.add_argument("--static", nargs="?", const=_STATIC_DEFAULT, default=None,
                    help=f"also write a self-contained static report (default {_STATIC_DEFAULT})")
    args = ap.parse_args()
    seed(args.id)
    if args.static:
        render_static(args.static, args.id)
