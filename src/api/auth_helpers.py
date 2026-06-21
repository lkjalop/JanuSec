"""Canonical auth helpers (State-extraction Step 3).

`_admin_ok` was copy-pasted into app.py and ~6 endpoint modules — if the admin-key check
ever needed a fix it had to be made in every copy. This is the single home; app.py and
the endpoint modules import `admin_ok` from here instead of each defining their own.
"""
from __future__ import annotations

import os

from fastapi import Request


def admin_ok(request: Request) -> bool:
    """True when the request carries the configured admin key. Single source of truth."""
    try:
        key = request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key")
        expected = os.getenv("ADMIN_API_KEY") or os.getenv("X_ADMIN_KEY")
        return bool(expected) and key == expected
    except Exception:
        return False


def admin_key_ok(x_admin_key: str | None) -> bool:
    """Key-string variant (for callers that already extracted the header value)."""
    try:
        expected = os.getenv("ADMIN_API_KEY") or os.getenv("X_ADMIN_KEY")
        return bool(expected) and x_admin_key == expected
    except Exception:
        return False
