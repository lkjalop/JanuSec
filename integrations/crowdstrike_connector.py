"""Minimal CrowdStrike connector stub for Phase 1.

This module provides a small Client class with methods expected by the rest of
the platform for future inbound pipelines. It's intentionally lightweight and
non-blocking; it can be expanded to call the real CrowdStrike APIs.
"""
from typing import Any, Dict, List
import os

class CrowdStrikeClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key or os.getenv('CROWDSTRIKE_API_KEY')
        self.base_url = base_url or os.getenv('CROWDSTRIKE_BASE_URL', 'https://api.crowdstrike.com')

    def ping(self) -> bool:
        """Lightweight health-check; in real implementation this would call an auth or simple endpoint."""
        # For now return True if api_key present
        return bool(self.api_key)

    def fetch_incidents(self, since: int | None = None) -> List[Dict[str, Any]]:
        """Stub for fetching incidents - returns empty list in demo mode."""
        # Real implementation would use OAuth2 and call /incidents or detections
        return []

    def map_alert_to_factors(self, alert: Dict[str, Any]) -> List[str]:
        """Convert a CrowdStrike alert into platform factor strings."""
        # Minimal mapping example
        facs = []
        try:
            typ = alert.get('type') or alert.get('event_type')
            if typ:
                facs.append(f'crowdstrike:type:{typ}')
            actor = alert.get('actor') or alert.get('user')
            if actor:
                facs.append(f'crowdstrike:actor:{actor}')
        except Exception:
            pass
        return facs

# Export a default client instance for convenience
CLIENT = CrowdStrikeClient()
