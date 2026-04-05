"""Test utilities exposed for pytest to avoid importing test modules directly."""
from typing import Any

try:
    from src.api.integrations_endpoints import wait_for_recent_ingest
except Exception:
    # Fallback stub
    def wait_for_recent_ingest(event_id: str, timeout: float = 2.0) -> dict[str, Any]:
        return {'found': False, 'elapsed': 0.0, 'recent': []}

__all__ = ['wait_for_recent_ingest']
