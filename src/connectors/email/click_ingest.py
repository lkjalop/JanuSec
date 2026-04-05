"""Backward-compatible shim: re-export unified click_store API."""
from __future__ import annotations

from .click_store import record_click, fetch_recent_clicks, add_click, enqueue_click, start_enrichment_worker

__all__ = ['record_click', 'fetch_recent_clicks', 'add_click', 'enqueue_click', 'start_enrichment_worker']
