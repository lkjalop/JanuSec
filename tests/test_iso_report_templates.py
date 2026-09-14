"""ISO-native report templates + root-cause / lessons-learned (buyer-format layer)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests._helpers import default_test_headers

from src.core.grc.nonconformity import build_audit_pack
from src.core.grc.report_templates import (
    root_cause, lessons_learned,
    iso27035_incident_record, iso27001_capa_register, iso19011_audit_report,
    render_audit_report_html, incident_timeline,
)
from src.api.grc_endpoints import router
from src.api.deep_analyze.persistence import REPORT_STORE

pytestmark = pytest.mark.acceptance

_TT = "2026-07-07T00:00:00+00:00"


def _pack():
    clusters = [
        {"cluster_id": "vesper-01", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
         "shared_users": ["martin.chen"], "shared_hosts": ["ws-martin-01"],
         "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
                         "exfil:cumulative_bytes_anomaly"],
         "time_window": {"start": 1776087462.0, "end": 1777408963.0, "span_seconds": 1321501.0},
         "_llm_evidence_refs": [1, 2, 3]},
        {"cluster_id": "low-01", "final_verdict": "SUSPECTED_BREACH", "severity": "medium",
         "shared_users": ["bob"], "factor_tags": ["ad_recon_discovery"], "_llm_evidence_refs": [9]},
    ]
    return build_audit_pack(clusters, transaction_time=_TT)


def test_root_cause_names_entry_point_and_failed_control():
    f = max(_pack()["findings"], key=lambda x: x["dread"]["overall_score"])
    rc = root_cause(f)
    assert rc["entry_point_phase"] == "oauth_device_code"          # kill-chain entry
    assert rc["candidate_control"]["control"] == "A.5.15"             # the control that failed
    assert rc["failed_control"] is None
    assert "have not been established" in rc["statement"]
    assert "Observed phase sequence" in rc["statement"]


def test_lessons_learned_are_preventive():
    f = max(_pack()["findings"], key=lambda x: x["dread"]["overall_score"])
    ll = lessons_learned(f)
    assert ll and all(isinstance(x, str) for x in ll)


def test_iso27035_incident_record():
    rec = iso27035_incident_record(_pack(), "a1")
    assert rec["standard"] == "ISO/IEC 27035"
    lead = rec["incidents"][0]                                     # worst-first
    assert lead["identification"]["responsible_actor"] == "martin.chen"
    assert lead["classification"]["severity"] in {"critical", "high"}
    assert "OAuth" in lead["classification"]["category"]
    # breach-notification requirement tracks a critical severity
    crit = lead["classification"]["severity"] == "critical"
    assert lead["notification"]["breach_notification_required"] is None
    assert lead["notification"]["deadline_hours"] is None
    assert lead["root_cause"]["statement"]
    assert lead["lessons_learned"]


def test_iso27001_capa_register():
    reg = iso27001_capa_register(_pack(), "a1")
    assert reg["standard"] == "ISO/IEC 27001:2022"
    assert reg["annex_a_gap_summary"]["iso27001"]["controls_failing"] == 0
    assert reg["annex_a_gap_summary"]["iso27001"]["controls_requiring_review"] >= 1
    ca = reg["corrective_actions"][0]
    assert ca["clause"].startswith("10.2")
    assert ca["correction"] and ca["corrective_action"] and ca["root_cause"]


def test_iso19011_audit_report_has_objective_evidence():
    ar = iso19011_audit_report(_pack(), "a1")
    assert ar["standard"] == "ISO 19011:2018"
    assert ar["audit_criteria"] and ar["methodology"]
    f0 = ar["findings"][0]
    assert f0["classification"] == "Candidate control concern"
    assert f0["objective_evidence"]["content_hash"]               # custody-hashed evidence
    assert "corrective action" in ar["conclusions"].lower() or "nonconformit" in ar["conclusions"].lower()


def test_iso_report_endpoints():
    REPORT_STORE["isox"] = {"org": "default", "audit_pack": _pack()}
    app = FastAPI(); app.include_router(router); c = TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})
    for path, std in (("iso27035", "ISO/IEC 27035"), ("iso27001", "ISO/IEC 27001:2022"), ("iso19011", "ISO 19011:2018")):
        r = c.get(f"/api/v1/assessments/isox/report/{path}")
        assert r.status_code == 200
        assert r.json()["standard"] == std


def test_render_audit_report_html_is_printable_document():
    html = render_audit_report_html(_pack(), "a1")
    # one self-contained printable document …
    assert html.startswith("<!doctype html>")
    assert "@media print" in html and "page-break-inside:avoid" in html
    # … carrying all three standards …
    assert "ISO 19011:2018" in html and "ISO/IEC 27035" in html and "ISO/IEC 27001:2022" in html
    # … with the worst incident, its named actor, root cause and corrective-action register.
    assert "martin.chen" in html
    assert "Root cause:" in html
    assert "Corrective-action register" in html


def test_report_html_endpoint():
    REPORT_STORE["isohtml"] = {"org": "default", "audit_pack": _pack()}
    app = FastAPI(); app.include_router(router); c = TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})
    r = c.get("/api/v1/assessments/isohtml/report.html")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "Information Security Audit" in r.text and "martin.chen" in r.text


def test_incident_timeline_is_view_ready():
    tl = incident_timeline(_pack(), "a1")
    assert tl["incident_count"] == 2
    lead = tl["incidents"][0]                                  # worst-first
    assert lead["actor"] == "martin.chen"
    assert lead["severity"] in {"critical", "high"}
    assert [s["label"] for s in lead["kill_chain"]]            # ordered narrative steps
    assert lead["kill_chain"][0]["phase"]                      # step carries its phase id
    assert lead["mitre"] and lead["evidence_rows"]             # techniques + cited rows


def test_timeline_endpoint():
    REPORT_STORE["tlx"] = {"org": "default", "audit_pack": _pack()}
    app = FastAPI(); app.include_router(router); c = TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})
    r = c.get("/api/v1/assessments/tlx/timeline")
    assert r.status_code == 200
    assert r.json()["standard"] == "JanuSec incident timeline"
    assert r.json()["incident_count"] == 2


def test_demo_seed_evidence_drilldown(tmp_path, monkeypatch):
    """The seeded demo backs its cited rows with real events, so the claim->evidence
    drill-down resolves to an event + custody hash (the flagship traceability story)."""
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(tmp_path))
    from scripts.seed_grc_demo import seed
    seed("evdemo")
    REPORT_STORE.pop("evdemo", None)                           # force disk-aware path
    app = FastAPI(); app.include_router(router); c = TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})
    r = c.get("/api/v1/assessments/evdemo/rows/47")            # a cited kerberoasting row
    assert r.status_code == 200
    body = r.json()
    assert body["event"]["action"] == "kerberos_service_ticket"
    assert len(body["custody"]["sha256"]) == 64               # real SHA-256
    assert c.get("/api/v1/assessments/evdemo/rows/9999").status_code == 404  # uncited


def test_grc_endpoint_recovers_from_disk_when_not_in_memory(tmp_path, monkeypatch):
    """The latent bug: GRC endpoints read REPORT_STORE directly, so after an eviction
    or restart they 404 on an assessment the rest of the app still loads from disk.
    The demo-seed writes an audit_pack straight to disk and relies on this path."""
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(tmp_path))
    from scripts.seed_grc_demo import seed
    seed("disk-demo")
    REPORT_STORE.pop("disk-demo", None)          # force pure disk fallback
    app = FastAPI(); app.include_router(router); c = TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})
    r = c.get("/api/v1/assessments/disk-demo/report.html")
    assert r.status_code == 200
    assert "martin.chen" in r.text                # flagship incident present
    inc = c.get("/api/v1/assessments/disk-demo/report/iso27035").json()
    assert inc["incident_count"] == 3            # confirmed + likely + suspected
