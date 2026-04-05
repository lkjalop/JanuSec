"""OpenCTI ingestion scaffold (production should use pycti).
Fallback deterministic output for tests.
"""
from typing import List, Dict

class OpenCTIAdapter:
    def __init__(self, url: str = None, token: str = None):
        self._url = url
        self._token = token

    def fetch_intrusion_sets(self) -> List[Dict]:
        # Production: GraphQL queries to OpenCTI
        return [{'name':'APT-Test','attack_patterns':['T1059.001','T1021']}]
