"""#2 Evidence drill-down + chain-of-custody: a cited row index resolves to the raw
event with a tamper-evident hash, and the audit pack carries a chain-of-custody digest."""
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


def test_row_drilldown_resolves_raw_event(client):
    REPORT_STORE["dd"] = {"org": "default", "evidence_rows": [
        {"row_index": 52, "user": "martin.chen", "event_name": "oauth_consent",
         "_source": "okta.json", "_source_type": "iam"},
    ]}
    r = client.get("/api/v1/assessments/dd/rows/52")
    assert r.status_code == 200
    b = r.json()
    assert b["event"]["user"] == "martin.chen"
    assert b["custody"]["source_file"] == "okta.json"
    assert len(b["custody"]["sha256"]) == 64
    # deterministic / verifiable
    assert client.get("/api/v1/assessments/dd/rows/52").json()["custody"]["sha256"] == b["custody"]["sha256"]


def test_missing_row_404(client):
    REPORT_STORE["dd2"] = {"org": "default", "evidence_rows": []}
    assert client.get("/api/v1/assessments/dd2/rows/999").status_code == 404


def test_pack_chain_of_custody_deterministic_and_tamper_evident():
    cl = [{"cluster_id": "c1", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
           "shared_users": ["martin.chen"], "factor_tags": ["kerberoasting"],
           "_llm_evidence_refs": [1, 2, 3]}]
    p1 = build_audit_pack([dict(c) for c in cl])
    p2 = build_audit_pack([dict(c) for c in cl])
    assert p1["custody"]["algorithm"] == "sha256"
    assert len(p1["custody"]["digest"]) == 64
    assert p1["custody"]["digest"] == p2["custody"]["digest"]      # deterministic
    tampered = [dict(c, _llm_evidence_refs=[9, 9, 9]) for c in cl]
    assert build_audit_pack(tampered)["custody"]["digest"] != p1["custody"]["digest"]  # tamper-evident
