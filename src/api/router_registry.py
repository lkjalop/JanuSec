"""Router registration helpers for the API application."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import FastAPI


def detect_route_collisions(app: FastAPI) -> dict[tuple[str, str], list[str]]:
    """Return every (method, path) registered on *app* more than once.

    A collision means two handlers claim the same route; FastAPI serves the first
    one mounted, so the winner depends on mount order. That is the root of several
    order-dependent bugs (e.g. an auth-enforcing handler shadowed by a permissive
    one). Use in a startup audit / test to fail fast instead of debugging a
    mysterious 200-that-should-be-401.

    Returns {(METHOD, path): [endpoint_name, ...]} for colliding routes only.
    """
    seen: Counter[tuple[str, str]] = Counter()
    endpoints: dict[tuple[str, str], list[str]] = {}
    for route in getattr(app, "routes", []):
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path:
            continue
        for method in methods:
            key = (method, path)
            seen[key] += 1
            name = getattr(getattr(route, "endpoint", None), "__name__", "?")
            endpoints.setdefault(key, []).append(name)
    return {k: endpoints[k] for k, c in seen.items() if c > 1}


def ensure_add_event_handler(app: FastAPI) -> None:
    """Provide ``add_event_handler`` on FastAPI/Starlette versions that lack it."""

    if hasattr(app, "add_event_handler"):
        return

    def _compat_add_event_handler(event_type: str, func: Any) -> Any:
        app.router.on_event(event_type)(func)
        return func

    app.add_event_handler = _compat_add_event_handler  # type: ignore[attr-defined]


def include_optional_router(app: FastAPI, router: Any, logger: Any, *, name: str) -> bool:
    """Best-effort router include with structured visibility."""

    if router is None:
        try:
            logger.debug("router_registry: optional router %s not available", name)
        except Exception:
            pass
        return False


def include_router_specs(app: FastAPI, specs: list[tuple[str, Any]], logger: Any) -> dict[str, bool]:
    """Include a sequence of named optional routers and return per-router status."""

    results: dict[str, bool] = {}
    for name, router in specs:
        results[name] = include_optional_router(app, router, logger, name=name)
    return results
    try:
        app.include_router(router)
        return True
    except Exception:
        try:
            logger.exception("router_registry: failed to include router %s", name)
        except Exception:
            pass
        return False
