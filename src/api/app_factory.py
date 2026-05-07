"""FastAPI application construction helpers.

This module keeps the raw FastAPI object creation out of ``app.py`` while
preserving the existing module-level application contract.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from fastapi import FastAPI


LifespanCallable = Callable[[FastAPI], AbstractAsyncContextManager[None] | AsyncIterator[None]]


def docs_urls_from_env() -> dict[str, str | None]:
    """Return FastAPI docs URL settings from the current environment."""

    enabled = os.environ.get("ENABLE_DOCS") == "1"
    return {
        "docs_url": "/docs" if enabled else None,
        "redoc_url": "/redoc" if enabled else None,
        "openapi_url": "/openapi.json" if enabled else None,
    }


def build_fastapi_app(
    *,
    title: str,
    version: str,
    lifespan: LifespanCallable | None = None,
    **overrides: Any,
) -> FastAPI:
    """Construct the canonical FastAPI app with shared defaults."""

    options = docs_urls_from_env()
    options.update(overrides)
    return FastAPI(
        title=title,
        version=version,
        lifespan=lifespan,
        **options,
    )
