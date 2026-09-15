"""CEO recording preflight test (P4).

Validates the full E2E plumbing an operator needs before a live demo:
  1. Server is reachable and reports Ollama as the LLM provider.
  2. qwen2.5:14b (or configured model) is listed in Ollama /api/tags.
  3. POST /api/v1/csv/deep_analyze accepts a small payload and returns an assessment_id.
  4. POST /assessments/{id}/investigate/build queues a job (status=queued or pending).
  5. GET /assessments/{id}/investigate/{inv_id} returns a valid status field.

Run with:  pytest tests/test_recording_preflight.py -v
Requires:  uvicorn server running on localhost:8765 + Ollama running on localhost:11434
Skip:      set SKIP_PREFLIGHT=1 to skip in CI environments without a live server.
"""
import os
import json
import time
import urllib.request
import urllib.error
import pytest

BASE = "http://localhost:8765"
OLLAMA = "http://localhost:11434"
TENANT = "preflight"
REQUIRED_MODEL = os.getenv("PREFLIGHT_MODEL", "qwen2.5:14b")

pytestmark = pytest.mark.skipif(
    os.getenv("SKIP_PREFLIGHT", "0").lower() in {"1", "true", "yes"},
    reason="SKIP_PREFLIGHT=1; skipping live server preflight",
)

HEADERS = {
    "Content-Type": "application/json",
    "X-Tenant-ID": TENANT,
}

MINIMAL_ROWS = [
    {
        "id": "pf-001",
        "log_source": "endpoint",
        "event_type": "process_spawn",
        "user": "alice@corp.local",
        "host": "WS-01",
        "ts": "2026-04-17T08:12:00Z",
        "process": "powershell.exe",
        "command_line": "powershell -ep bypass -enc AABB",
        "severity": "high",
        "mitre_technique": "T1059.001",
        "analyst_notes": "Encoded PS from lnk file",
    },
    {
        "id": "pf-002",
        "log_source": "endpoint",
        "event_type": "lsass_access",
        "user": "alice@corp.local",
        "host": "WS-01",
        "ts": "2026-04-17T08:13:30Z",
        "process": "procdump.exe",
        "target_process": "lsass.exe",
        "severity": "critical",
        "mitre_technique": "T1003.001",
        "analyst_notes": "procdump targeting LSASS",
    },
]


def _api(method: str, path: str, body=None, timeout: int = 30):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        pytest.skip(f"Server not reachable: {e}")


def test_server_health():
    """Server must be up and reporting ollama as LLM provider."""
    status, body = _api("GET", "/health")
    assert status == 200, f"health returned {status}"
    llm = body.get("llm", {})
    assert llm.get("ollama_enabled") or llm.get("provider") == "ollama", (
        f"Ollama not enabled in health: {llm}"
    )
    assert llm.get("ollama_reachable"), f"Ollama not reachable: {llm}"


def test_ollama_model_present():
    """Required model must be present in Ollama."""
    try:
        req = urllib.request.Request(f"{OLLAMA}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f"Ollama not reachable at {OLLAMA}: {e}")

    models = [m.get("name", "") for m in data.get("models", [])]
    assert any(REQUIRED_MODEL in m for m in models), (
        f"Required model '{REQUIRED_MODEL}' not found in Ollama. Available: {models}"
    )


def test_deep_analyze_accepts_payload():
    """POST /api/v1/csv/deep_analyze must return an assessment_id."""
    status, body = _api(
        "POST",
        "/api/v1/csv/deep_analyze",
        {"rows": MINIMAL_ROWS, "org": TENANT, "auto_llm": False},
        timeout=60,
    )
    assert status == 200, f"deep_analyze returned {status}: {body}"
    assessment_id = body.get("assessment_id") or body.get("id")
    assert assessment_id, f"No assessment_id in response: {body}"
    # Store for downstream tests via module-level variable
    _ctx["assessment_id"] = assessment_id


_ctx = {}  # shared across tests in this module


def test_investigate_build_queues():
    """POST investigate/build must return queued or pending status."""
    aid = _ctx.get("assessment_id")
    if not aid:
        pytest.skip("assessment_id not available — run test_deep_analyze_accepts_payload first")

    status, body = _api(
        "POST",
        f"/api/v1/assessments/{aid}/investigate/build",
        {"model": REQUIRED_MODEL},
        timeout=30,
    )
    assert status == 200, f"investigate/build returned {status}: {body}"
    inv_id = body.get("investigate_id")
    assert inv_id, f"No investigate_id in response: {body}"
    job_status = body.get("status", "")
    assert job_status in {"queued", "pending", "processing", "ready"}, (
        f"Unexpected initial status: {job_status}"
    )
    _ctx["investigate_id"] = inv_id


def test_investigate_status_readable():
    """GET investigate/{id} must return a valid status field."""
    aid = _ctx.get("assessment_id")
    inv_id = _ctx.get("investigate_id")
    if not aid or not inv_id:
        pytest.skip("No investigate_id — run preceding tests first")

    status, body = _api(
        "GET",
        f"/api/v1/assessments/{aid}/investigate/{inv_id}",
        timeout=10,
    )
    assert status == 200, f"investigate status returned {status}: {body}"
    assert "status" in body, f"No status field in response: {body}"
    assert body["status"] in {
        "queued", "pending", "processing", "ready", "failed", "unknown"
    }, f"Unknown status value: {body['status']}"
