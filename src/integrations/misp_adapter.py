"""MISP ingestion scaffold using PyMISP (production implementation should install pymisp).
This scaffold provides a fallback implementation for tests which returns deterministic
results. Replace the fallback with real PyMISP calls in production.
"""
from typing import List, Dict

class MISPAdapter:
    def __init__(self, url: str = None, key: str = None):
        self._url = url
        self._key = key
        # deterministic test feed
        self._domains = ['evil.example']

    def fetch_recent_iocs(self, hours: int = 24) -> Dict[str, List[str]]:
        # In production: call PyMISP and parse attributes
        return {'domains': list(self._domains), 'ips': ['1.2.3.4']}
