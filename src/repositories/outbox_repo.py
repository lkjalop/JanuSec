"""Outbox repository facade.

Exposes a simple API expected by the dispatcher background retry loop.
For now, this forwards to the SQLite implementation when OUTBOX_BACKEND is
set to 'sqlite' (default), but can be extended to Postgres in the future.
"""
from __future__ import annotations

import os

backend = (os.getenv('OUTBOX_BACKEND') or 'sqlite').lower()

if backend in ('sqlite','db'):
    from .outbox_repo_sqlite import enqueue, next_pending, mark_done, mark_done_by_key, fail  # noqa: F401
else:  # fallback to sqlite
    from .outbox_repo_sqlite import enqueue, next_pending, mark_done, mark_done_by_key, fail  # noqa: F401
