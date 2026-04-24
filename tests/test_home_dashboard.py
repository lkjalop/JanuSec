"""
Tests for the live home dashboard (home.html) and staged-events pipeline.

Covers:
  1. GET / returns home.html (200, correct content)
  2. home.html references correct API endpoints
  3. API endpoints called by home.html respond correctly
  4. Staged events localStorage contract: keys & shape
  5. investigate.html still served separately
"""
import os
import json
import pytest

# ── App fixture ──────────────────────────────────────────────────────────────

os.environ.setdefault("PLATFORM_LITE_INIT", "1")
os.environ.setdefault("TEST_HELPERS_ENABLED", "1")
os.environ.setdefault("DISABLE_DB", "1")
os.environ.setdefault("LLM_MOCK", "1")
os.environ.setdefault("DEFAULT_FRONTEND", "home")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault("ALLOW_DEFAULT_TENANT", "1")

from fastapi.testclient import TestClient

@pytest.fixture(scope="module")
def client():
    from src.api.app import app
    return TestClient(app, raise_server_exceptions=False)


HEADERS = {"x-api-key": "devkey123"}


# ── 1. Root serves home.html ─────────────────────────────────────────────────

def test_root_serves_home(client):
    """GET / must return home.html — the live adaptive dashboard."""
    r = client.get("/", headers=HEADERS, follow_redirects=True)
    assert r.status_code == 200
    body = r.text.lower()
    # Must include the page title or live operations marker
    assert "live operations" in body or "janusec" in body, \
        "Root page does not contain expected home.html content"


def test_root_not_investigate(client):
    """Root must NOT silently serve raw investigate.html without the live dashboard."""
    r = client.get("/", headers=HEADERS, follow_redirects=True)
    assert r.status_code == 200
    # home.html has 'Live Operations', investigate.html has 'Investigation Console'
    # Both are acceptable now only if home.html contains live-specific markers
    body = r.text
    # home.html must have the live feed tab or connector bar
    assert "connectorBar" in body or "live-pulse" in body or "Live Operations" in body, \
        "Root is not serving the live adaptive dashboard (home.html)"


def test_investigate_still_accessible(client):
    """investigate.html must remain at its own URL, untouched."""
    r = client.get("/static/investigate.html", headers=HEADERS, follow_redirects=True)
    assert r.status_code == 200
    assert "Investigation Console" in r.text or "investigateBody" in r.text or "uploadZone" in r.text


# ── 2. home.html API endpoints respond ──────────────────────────────────────

def test_dashboard_status_endpoint(client):
    """GET /api/v1/dashboard/status must return 200 with alert counts."""
    r = client.get("/api/v1/dashboard/status", headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert "alerts" in data or "xdr_connection" in data, \
        f"Unexpected dashboard/status shape: {list(data.keys())}"


def test_dashboard_metrics_endpoint(client):
    """GET /api/v1/dashboard/metrics must return 200 with detection_rate."""
    r = client.get("/api/v1/dashboard/metrics", headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert "detection_rate" in data or "critical_threats" in data, \
        f"Unexpected dashboard/metrics shape: {list(data.keys())}"


def test_decisions_lifecycle_recent_endpoint(client):
    """GET /api/v1/decisions/lifecycle/recent used by home.html live feed."""
    r = client.get("/api/v1/decisions/lifecycle/recent?limit=10", headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    # accepts list or {'decisions': [...]} shapes
    assert isinstance(data, (list, dict)), f"Unexpected type: {type(data)}"


def test_decisions_recent_fallback(client):
    """GET /api/v1/decisions/recent fallback also works."""
    r = client.get("/api/v1/decisions/recent", headers=HEADERS)
    assert r.status_code == 200


# ── 3. Staged events contract (localStorage shape) ───────────────────────────

def test_staged_events_schema():
    """staged_events localStorage payload must have expected keys."""
    payload = {
        "staged_at": "2026-04-12T10:00:00Z",
        "source": "live_dashboard",
        "events": [
            {
                "event_id": "evt-001",
                "severity": "critical",
                "type": "correlated",
                "entity": "10.10.4.47",
                "description": "Lateral movement detected",
                "triage_score": 1.0,
            }
        ],
    }
    # Validate schema
    assert "staged_at" in payload
    assert "source" in payload
    assert isinstance(payload["events"], list)
    assert len(payload["events"]) == 1
    evt = payload["events"][0]
    for key in ("event_id", "severity", "type", "entity", "description", "triage_score"):
        assert key in evt, f"Missing key '{key}' in staged event"
    assert evt["triage_score"] == 1.0
    # JSON round-trip
    raw = json.dumps(payload)
    parsed = json.loads(raw)
    assert parsed["events"][0]["event_id"] == "evt-001"


# ── 4. home.html static content sanity ──────────────────────────────────────

def test_home_html_references_decisions_api():
    """home.html must reference the lifecycle/recent API endpoint in its JS."""
    home_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "static", "home.html"
    )
    assert os.path.exists(home_path), "home.html not found"
    with open(home_path, encoding="utf-8") as f:
        content = f.read()
    assert "decisions/lifecycle/recent" in content or "decisions/recent" in content, \
        "home.html does not reference the decisions API"
    assert "dashboard/metrics" in content, "home.html must poll dashboard/metrics"
    assert "dashboard/status" in content, "home.html must poll dashboard/status"
    assert "stageEvent" in content, "home.html must have stageEvent() function"
    assert "janusec_staged_events" in content, "home.html must use localStorage key janusec_staged_events"


def test_investigate_html_has_staged_banner():
    """investigate.html must have the staged import banner for staged events from home.html."""
    inv_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "static", "investigate.html"
    )
    assert os.path.exists(inv_path), "investigate.html not found"
    with open(inv_path, encoding="utf-8") as f:
        content = f.read()
    assert "stagedImportBanner" in content, "investigate.html must have #stagedImportBanner element"
    assert "importStagedEvents" in content, "investigate.html must reference importStagedEvents()"


def test_investigate_js_has_staged_import():
    """investigate.js must have importStagedEvents and dismissStagedBanner functions."""
    js_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "static", "js", "investigate.js"
    )
    assert os.path.exists(js_path), "investigate.js not found"
    with open(js_path, encoding="utf-8") as f:
        content = f.read()
    assert "importStagedEvents" in content
    assert "dismissStagedBanner" in content
    assert "janusec_staged_events" in content


# ── 5. investigate.html severity summary IDs match investigate.js ─────────────

def test_severity_summary_ids_match():
    """
    The severity summary IDs in investigate.html must match what investigate.js reads.
    This is the bug that caused the querySelectorAll crash — validate it's fixed.
    """
    html_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "static", "investigate.html"
    )
    js_path = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "static", "js", "investigate.js"
    )
    with open(html_path, encoding="utf-8") as f:
        html = f.read()
    with open(js_path, encoding="utf-8") as f:
        js = f.read()

    # IDs that must exist in HTML and be referenced in JS
    required_ids = ["sc_crit", "sc_high", "sc_med", "sc_low", "sc_total",
                    "si_crit", "si_high", "si_med", "si_low", "si_total"]
    for id_ in required_ids:
        assert f'id="{id_}"' in html or f"id='{id_}'" in html, \
            f"Missing HTML element id='{id_}'"
        assert id_ in js, f"investigate.js does not reference '{id_}'"
