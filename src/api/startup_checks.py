"""Startup checks that should be visible and reusable outside ``app.py``."""

from __future__ import annotations

import os
from typing import Any


def is_live_environment() -> bool:
    return os.getenv("ENV", "").lower() in {"staging", "prod", "production"} or os.getenv(
        "APP_ENV", ""
    ).lower() in {"staging", "prod", "production"}


def apply_config_profile(logger: Any) -> None:
    """Apply CONFIG_PROFILE if configured.

    Profile loading is optional, but failures are logged as warnings instead of
    being hidden as debug-only startup noise.
    """

    try:
        from src.config.profile_loader import apply_profile

        profile = os.getenv("CONFIG_PROFILE")
        if profile:
            apply_profile(profile)
    except Exception:
        try:
            logger.warning("startup_checks: CONFIG_PROFILE apply failed", exc_info=True)
        except Exception:
            pass


async def initialize_database(logger: Any) -> None:
    """Initialize the platform DB pool and run migrations when configured."""

    enabled = os.getenv("USE_PLATFORM_DB", "0").lower() in {"1", "true", "yes"} or bool(
        os.getenv("APP_DB_DSN")
    )
    if not enabled:
        return

    live_mode = is_live_environment()
    try:
        try:
            from src.db import database as db
        except Exception:
            import db.database as db  # type: ignore

        await db.init_pool()
        logger.info("lifespan: database pool initialized")

        try:
            from src.db.migrations import apply_migrations_postgres, apply_migrations_sqlite
        except Exception:
            try:
                from db.migrations import apply_migrations_postgres, apply_migrations_sqlite  # type: ignore
            except Exception:
                apply_migrations_postgres = apply_migrations_sqlite = None  # type: ignore

        try:
            pool = await db.get_pool()
            if hasattr(db, "is_fallback_active") and db.is_fallback_active():
                if apply_migrations_sqlite:
                    async with pool.acquire() as conn:  # type: ignore[attr-defined]
                        await apply_migrations_sqlite(conn)
            elif apply_migrations_postgres:
                await apply_migrations_postgres(pool)
        except Exception:
            logger.exception("lifespan: database migrations failed")
            if live_mode:
                raise
    except Exception:
        logger.exception("lifespan: database initialization failed")
        if live_mode:
            raise
