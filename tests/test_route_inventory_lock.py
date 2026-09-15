"""Characterization lock for the lite/test app's route set.

Before consolidating the 3 router-mounting layers into one manifest, we pin the
exact set of (method, path) the current wiring produces. Any add/remove then shows
up here as an explicit diff — so a refactor that drops or duplicates a route fails
loudly instead of silently 404-ing (the failure mode the ~1,191 silent_swallow
handlers otherwise hide).

This is a GOLDEN test: when you intentionally add/remove a route, regenerate
tests/fixtures/route_inventory_lite.json in the same commit (see _regenerate()).
"""
from __future__ import annotations

import json
from pathlib import Path

from src.api.server import app

_GOLDEN = Path(__file__).parent / "fixtures" / "route_inventory_lite.json"


def _current_routes() -> set[str]:
    return {
        f"{m} {getattr(r, 'path', '')}"
        for r in app.routes
        for m in (getattr(r, "methods", None) or {"GET"})
        if getattr(r, "path", "")
    }


def _regenerate() -> None:  # pragma: no cover - dev helper
    _GOLDEN.write_text(json.dumps(sorted(_current_routes()), indent=1), encoding="utf-8")


def test_lite_route_inventory_no_removals():
    """No route in the golden baseline may DISAPPEAR.

    Additions are tolerated: the app is a process-wide singleton and tests that call
    create_app() mount extra routers onto it during the session, so the live set
    legitimately grows depending on what ran (itself the singleton-mutation problem
    Phase 3b targets). A REMOVAL, however, means a refactor dropped a route — exactly
    the silent-404 drift this lock exists to catch.
    """
    import os
    if os.getenv("JANUSEC_REGEN_ROUTE_GOLDEN", "0") == "1":  # pragma: no cover
        _regenerate()
        return
    golden = set(json.loads(_GOLDEN.read_text(encoding="utf-8")))
    removed = sorted(golden - _current_routes())
    assert not removed, (
        f"{len(removed)} route(s) from the golden baseline are no longer registered — "
        f"a refactor dropped them (silent 404 in prod):\n{removed[:30]}\n"
        "If intentional, regenerate tests/fixtures/route_inventory_lite.json in this commit."
    )
