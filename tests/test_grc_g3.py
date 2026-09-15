"""G3: MITRE Navigator export + AI-governance self-assessment (ISO 42001 / EU AI Act /
MAESTRO). Both are robust-by-construction — the Navigator is a pure transform of the
findings' MITRE, the governance posture is platform-level and input-independent."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests._helpers import default_test_headers

from src.core.grc.mitre_navigator import build_navigator_layer
from src.core.grc.ai_governance import ai_governance_posture, ai_surface_maestro
from src.core.grc.nonconformity import build_audit_pack
from src.api.grc_endpoints import router
from src.api.deep_analyze.persistence import REPORT_STORE

pytestmark = pytest.mark.acceptance


def _pack():
    clusters = [
        {"cluster_id": "c1", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
         "shared_users": ["martin.chen"],
         "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral"]},
        {"cluster_id": "c2", "final_verdict": "VALIDATED_BREACH", "severity": "high",
         "shared_users": ["priya.shah"], "factor_tags": ["oauth_device_code"]},
    ]
    return build_audit_pack(clusters)


def test_navigator_layer_is_valid_and_transforms_findings():
    layer = build_navigator_layer(_pack(), name="test")
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1528" in ids and "T1047" in ids and "T1558.003" in ids   # real detected techniques
    # T1528 (OAuth) appears in both findings -> score 2, aggregated across actors
    t1528 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1528")
    assert t1528["score"] == 2
    assert "martin.chen" in t1528["comment"] and "priya.shah" in t1528["comment"]
    # every technique has a colour + gradient
    assert all(t.get("color") for t in layer["techniques"])
    assert layer["gradient"]["maxValue"] >= 1


def test_navigator_empty_when_no_findings():
    layer = build_navigator_layer({"findings": []})
    assert layer["techniques"] == []


def test_ai_governance_posture_is_honest_and_framework_mapped():
    p = ai_governance_posture()
    assert p["summary"]["total_controls"] == len(p["controls"]) >= 8
    # honest: statuses are real, not all 'implemented'
    statuses = {c["status"] for c in p["controls"]}
    assert "implemented" in statuses
    assert p["summary"]["implemented"] + p["summary"]["partial"] + p["summary"]["planned"] == p["summary"]["total_controls"]
    # every control cites a code mechanism + at least one framework
    for c in p["controls"]:
        assert c["mechanism"]
        assert c["iso42001"] or c["eu_ai_act"]
    # framework coverage surfaced
    assert p["summary"]["iso42001_controls"]
    assert any("Art." in a for a in p["summary"]["eu_ai_act_articles"])


def test_ai_surface_maestro_maps_detected_ai_phases():
    pack = build_audit_pack([
        {"cluster_id": "ai1", "final_verdict": "VALIDATED_BREACH", "severity": "high",
         "shared_users": ["agent-x"], "factor_tags": ["mcp_tool_abuse"]},
    ])
    surface = ai_surface_maestro(pack)
    layers = surface["detected_ai_surface"]
    assert any("Agent" in k for k in layers)   # mcp_tool_abuse -> agent layers


@pytest.fixture
def client():
    app = FastAPI(); app.include_router(router)
    return TestClient(app, headers={**default_test_headers(), "x-tenant-id": "default"})


def test_navigator_and_governance_endpoints(client):
    REPORT_STORE["g3"] = {"org": "default", "audit_pack": _pack()}
    nav = client.get("/api/v1/assessments/g3/mitre-navigator")
    assert nav.status_code == 200 and nav.json()["domain"] == "enterprise-attack"
    gov = client.get("/api/v1/ai-governance")
    assert gov.status_code == 200 and gov.json()["summary"]["total_controls"] >= 8
    surf = client.get("/api/v1/assessments/g3/ai-surface")
    assert surf.status_code == 200
