from __future__ import annotations

import json
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.perf_api_stage import router as perf_router


def test_api_stage_artifact_endpoint_lists_entries(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    payload = {
        "entries": [
            {"ts": 3, "tenant": "alpha", "files": {"benchmark": "bench-alpha.json"}},
            {"ts": 1, "tenant": "bravo"},
        ]
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("API_STAGE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")

    app = FastAPI()
    app.include_router(perf_router)
    client = TestClient(app)

    resp = client.get("/api/v1/perf/api_stage/artifacts?limit=1&include_profiles=true", headers={"x-api-key": "devkey123"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["artifacts"]) == 1
    assert data["artifacts"][0]["tenant"] == "alpha"
    assert "pipeline_profiles" in data
