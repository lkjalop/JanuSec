"""Drift guards: pin the public surface of heavily-refactored modules.

Two refactor-drift bugs this session (REPORT_STORE silently un-bounded; helpers
removed but still pinned by tests) shared a cause: a big file was split / rewritten
and a symbol or invariant quietly disappeared, with nothing failing at the seam —
only a downstream test pinning a ghost. These contracts fail LOUDLY at the source
module the moment a documented symbol/invariant is removed.

Keep these in sync with deliberate API changes; a failure here means either a real
regression or an intentional change that should update this file in the same commit.
"""
from __future__ import annotations

import importlib


def test_deep_analyze_endpoints_public_surface():
    # Other modules import these from deep_analyze_endpoints (re-export shim). If a
    # refactor drops one, importers break far away; assert it here instead.
    dae = importlib.import_module("src.api.deep_analyze_endpoints")
    required = [
        "REPORT_STORE", "PARENT_CHILD_INDEX", "_BoundedDict",
        "_persist_assessment_state", "_get_assessment_cached",
        "_write_assessment_index", "_load_assessment_from_disk",
    ]
    missing = [name for name in required if not hasattr(dae, name)]
    assert not missing, f"deep_analyze_endpoints lost public symbols: {missing}"


def test_report_store_is_bounded_not_plain_dict():
    # The Phase A refactor turned REPORT_STORE into a plain unbounded dict (latent
    # OOM). It must stay a bounded type so a long-running process can't grow it
    # without limit. This invariant has no other automated guard.
    from src.api.deep_analyze import persistence as P
    assert isinstance(P.REPORT_STORE, P._BoundedDict), (
        "REPORT_STORE must be a bounded dict — a plain dict reintroduces the "
        "unbounded-growth memory leak."
    )
    assert getattr(P.REPORT_STORE, "_maxsize", 0) > 0


def test_router_registry_actually_mounts():
    # Regression guard for the dead-code bug where include_optional_router fell
    # through and never called app.include_router.
    from fastapi import FastAPI, APIRouter
    from src.api.router_registry import include_optional_router
    import logging

    app = FastAPI()
    r = APIRouter()

    @r.get("/_contract_probe")
    def _probe():
        return {"ok": True}

    ok = include_optional_router(app, r, logging.getLogger("test"), name="probe")
    assert ok is True
    assert any(getattr(rt, "path", "") == "/_contract_probe" for rt in app.routes)
    # None router is a no-op that returns False (not an exception).
    assert include_optional_router(app, None, logging.getLogger("test"), name="absent") is False
