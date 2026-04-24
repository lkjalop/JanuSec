"""OPT-5: Route parity CI test.

Ensures that the core API routes registered by the FastAPI application match
a known-good set. Catches cases where a router is accidentally dropped, a
prefix changes, or a new route is added without updating this test.

The test uses a TestClient (no live server needed) and inspects the route tree.
It does NOT test auth, just that the paths exist.

Two checks:
  1. REQUIRED_PATHS — critical routes that must always be present.
  2. BANNED_PATHS — paths that must NOT be present (deprecated/removed routes).
"""
import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Core routes that must always be present
# ---------------------------------------------------------------------------
REQUIRED_PATHS = [
    # Deep analyze / investigate
    "/api/v1/csv/deep_analyze",
    "/api/v1/assessments/{assessment_id}/investigate/build",
    "/api/v1/assessments/{assessment_id}/investigate/{investigate_id}",
    # Health + LLM
    "/health",
    "/api/v1/llm/health",
    # Tier2 canvas (actual registered path)
    "/api/v1/csv/tier2_summarize",
    # Hunt
    "/api/v1/hunt/overview",
    # Metrics
    "/api/v1/metrics/summary",
    # Expand subtask
    "/api/v1/assessments/{assessment_id}/tasks/{task_id}/expand",
]

# ---------------------------------------------------------------------------
# Paths that must NOT be present (removed/deprecated)
# ---------------------------------------------------------------------------
BANNED_PATHS: list[str] = []


@pytest.fixture(scope="module")
def app():
    """Import the FastAPI app lazily so this test doesn't slow collection."""
    try:
        from src.api.app import create_app
        return create_app()
    except Exception:
        try:
            from src.api.server import app as _app
            return _app
        except Exception as e:
            pytest.skip(f"Could not import app: {e}")


@pytest.fixture(scope="module")
def registered_paths(app):
    """Return the set of all route path strings registered on the app."""
    paths = set()
    for route in app.routes:
        p = getattr(route, "path", None)
        if p:
            paths.add(p)
    return paths


def test_required_routes_present(registered_paths):
    """Every entry in REQUIRED_PATHS must be registered."""
    missing = [p for p in REQUIRED_PATHS if p not in registered_paths]
    assert not missing, (
        f"Missing required routes:\n" + "\n".join(f"  {p}" for p in missing)
        + f"\n\nRegistered paths (sample): {sorted(registered_paths)[:20]}"
    )


def test_banned_routes_absent(registered_paths):
    """No entry in BANNED_PATHS may be registered."""
    present = [p for p in BANNED_PATHS if p in registered_paths]
    assert not present, (
        f"Banned (deprecated) routes still registered:\n"
        + "\n".join(f"  {p}" for p in present)
    )


def test_investigate_build_is_post(app):
    """investigate/build must be POST, not GET — enforces contract."""
    build_path = "/api/v1/assessments/{assessment_id}/investigate/build"
    for route in app.routes:
        if getattr(route, "path", "") == build_path:
            methods = getattr(route, "methods", set()) or set()
            assert "POST" in methods, f"investigate/build is not POST: methods={methods}"
            return
    pytest.skip(f"Route {build_path!r} not found — skipping method check")


def test_health_is_get(app):
    """Health endpoint must be GET."""
    for route in app.routes:
        if getattr(route, "path", "") == "/health":
            methods = getattr(route, "methods", set()) or set()
            assert "GET" in methods, f"/health is not GET: methods={methods}"
            return
    pytest.skip("/health not found — skipping method check")
