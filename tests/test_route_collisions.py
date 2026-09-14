"""Guardrail: no NEW duplicate route registrations.

A (method, path) registered twice means FastAPI serves whichever handler mounted
first — so behaviour depends on mount order (= import/test order). This class of
bug produced a real auth bypass (a permissive label handler shadowing the
auth-enforcing one). This test pins the known collision set so any newly
introduced duplicate fails immediately instead of becoming a heisenbug.

The allowlist should only shrink. When a collision is fixed, remove it here.
"""
from __future__ import annotations

from src.api.server import app
from src.api.router_registry import detect_route_collisions


# Known, pre-existing collisions in the lite/test app. Each is tracked for removal
# (Phase 0c). Do NOT add to this list — fix the duplicate registration instead.
_ALLOWED_COLLISIONS = {
    ("GET", "/api/v1/health"),  # api_health_alias + platform_health (intentional alias)
}


def test_no_new_route_collisions():
    collisions = detect_route_collisions(app)
    unexpected = {k: v for k, v in collisions.items() if k not in _ALLOWED_COLLISIONS}
    assert not unexpected, (
        "New duplicate route registration(s) — FastAPI serves the first by mount "
        "order, making behaviour order-dependent. Fix the duplicate or, if truly "
        f"intentional, add to _ALLOWED_COLLISIONS with justification:\n{unexpected}"
    )

# NB: we intentionally do NOT assert the allowlist is non-stale (i.e. that every
# allowlisted pair still collides). Whether a given route collides depends on which
# modules are imported and the lite/full mode, so that reverse check is itself
# order-dependent. A superset allowlist is harmless; only NEW collisions matter.
