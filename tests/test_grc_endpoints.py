"""GRC / Control-Assurance endpoints: JSON + CSV + standalone HTML from the audit pack."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests._helpers import default_test_headers

from src.api.grc_endpoints import router
from src.api.deep_analyze.persistence import REPORT_STORE
from src.core.grc.nonconformity import build_audit_pack

pytestmark = pytest.mark.acceptance


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})


def _seed(aid: str):
    cluster = {
        "cluster_id": "vesper-01", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
        "shared_users": ["martin.chen"], "shared_hosts": ["ws-martin-01"],
        "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
                        "exfil:cumulative_bytes_anomaly"],
        "_llm_evidence_refs": [52, 20430, 20431],
    }
    pack = build_audit_pack([cluster])
    REPORT_STORE[aid] = {"org": "default", "audit_pack": pack, "nonconformities": pack["nonconformities"]}
    return pack


def test_audit_pack_json(client):
    _seed("a1")
    r = client.get("/api/v1/assessments/a1/audit-pack")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total_findings"] >= 1
    assert body["summary"]["p1_count"] >= 1
    # decomposed DREAD + drivers reach the wire
    f = body["findings"][0]
    assert "damage" in f["dread"]["components"]
    assert f["drivers"]["investments"]


def test_audit_pack_csv(client):
    _seed("a2")
    r = client.get("/api/v1/assessments/a2/audit-pack.csv")
    assert r.status_code == 200
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("nc_id,priority,sla_hours")
    assert len(lines) >= 2
    assert "audit-pack-a2.csv" in r.headers.get("content-disposition", "")


def test_audit_pack_html(client):
    _seed("a3")
    r = client.get("/api/v1/assessments/a3/audit-pack.html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    for token in ("Control Assurance", "Damage", "Affected", "CISO budget", "martin.chen",
                  "Framework Gap", "Access control"):
        assert token in r.text


def test_missing_assessment_404(client):
    r = client.get("/api/v1/assessments/does-not-exist/audit-pack")
    assert r.status_code == 404


def test_assessment_without_breach_returns_empty_pack(client):
    REPORT_STORE["a4"] = {"org": "default", "verdict": "BENIGN_EXPECTED"}  # no audit_pack
    r = client.get("/api/v1/assessments/a4/audit-pack")
    assert r.status_code == 200
    assert r.json()["summary"]["total_findings"] == 0
