"""Declarative router manifest — the single source of truth for API mounting.

Router mounting historically lived across three non-agreeing layers (the
register_core_routers full/lite split, the create_app _lite_include_router prefix
allowlist, and ~12 ad-hoc "ensure X router" blocks). They diverged silently, which
caused 404s (a router only in the skipped layer) and order-dependent auth bugs.

This manifest centralises the wiring as DATA: each router declared once, with the
tiers it belongs to. ``mount_manifest`` is the one loop that reads it. Routers are
migrated into the manifest incrementally (strangler); the route-inventory lock and
collision detector guarantee no route is dropped or duplicated during migration.

Tiers:
  - 'lite' : mounted under PLATFORM_LITE_INIT / pytest (import-light only — these
             load without heavy ML/IO deps, keeping test collection fast).
  - 'full' : mounted in normal/production startup.
A router in both tiers is always available.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass


@dataclass(frozen=True)
class RouterSpec:
    name: str
    import_path: str  # "module.path:attr"
    tiers: frozenset[str]


_BOTH = frozenset({"lite", "full"})

# Single source of truth. Add a router HERE (once) instead of in the lite block,
# the directly-included loop, or a create_app defensive block. Keep 'lite' entries
# import-light. The list grows as routers are migrated off the legacy layers.
ROUTER_MANIFEST: list[RouterSpec] = [
    RouterSpec("risk", "src.api.risk_endpoints:router", _BOTH),
    RouterSpec("supply_chain", "src.api.supply_chain_endpoints:router", _BOTH),
    RouterSpec("suppression_admin", "src.api.suppression_admin_endpoints:router", _BOTH),
    RouterSpec("analytics", "src.api.analytics_endpoints:router", _BOTH),
]


def mount_manifest(app, tier: str, logger=None) -> list[str]:
    """Mount every manifest router whose tiers include *tier*. Idempotent w.r.t. the
    app's own dedupe. Returns the list of router names successfully mounted."""
    mounted: list[str] = []
    for spec in ROUTER_MANIFEST:
        if tier not in spec.tiers:
            continue
        try:
            mod_path, attr = spec.import_path.split(":", 1)
            module = importlib.import_module(mod_path)
            router = getattr(module, attr, None)
            if router is not None:
                app.include_router(router)
                mounted.append(spec.name)
        except Exception:
            if logger is not None:
                logger.debug("manifest: failed to mount %s", spec.name, exc_info=True)
    return mounted
