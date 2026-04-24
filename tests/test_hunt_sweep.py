from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import runtime_state
from src.api.hunt_endpoints import router


def test_hunt_sweep_matches_cached_decisions_and_generates_queries():
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    runtime_state.DECISION_CACHE.clear()
    runtime_state.DECISION_CACHE["evt-1"] = {
        "event_id": "evt-1",
        "tenant_id": "default",
        "severity": "critical",
        "dst_ip": "198.51.100.44",
        "domain": "c2.example.test",
        "summary": "Beacon to known C2 infrastructure",
    }
    runtime_state.DECISION_CACHE["evt-2"] = {
        "event_id": "evt-2",
        "tenant_id": "other",
        "dst_ip": "198.51.100.44",
        "summary": "Same pivot in another tenant",
    }

    resp = client.post(
        "/api/v1/hunt/sweep",
        json={
            "tenant_id": "default",
            "scope": "tenant",
            "iocs": {"ips": ["198.51.100.44"], "domains": ["c2.example.test"]},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["count"] == 1
    assert body["matches"][0]["event_id"] == "evt-1"
    assert "198.51.100.44" in body["generated_queries"]["kql"]
    assert "c2.example.test" in body["generated_queries"]["spl"]

    resp_all = client.post(
        "/api/v1/hunt/sweep",
        json={
            "tenant_id": "default",
            "scope": "all_tenants",
            "query": "show me every tenant with 198.51.100.44",
        },
    )
    assert resp_all.status_code == 200
    assert resp_all.json()["count"] == 2
