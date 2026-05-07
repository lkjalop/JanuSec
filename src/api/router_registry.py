"""Router registration helpers for the API application."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI


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
