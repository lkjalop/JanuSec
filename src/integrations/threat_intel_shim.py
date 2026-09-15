"""Deterministic threat-intel shim for tests (MISP/OpenCTI emulation).
"""
from typing import List, Dict

class ThreatIntelShim:
    def __init__(self, *args, **kwargs):
        # maintain a small deterministic set
        self._ips = ['1.2.3.4']
        self._domains = ['evil.example']

    def lookup_ip(self, ip: str) -> Dict:
        return {'ip': ip, 'malicious': ip in self._ips}

    def lookup_domain(self, dom: str) -> Dict:
        return {'domain': dom, 'malicious': dom in self._domains}

    def get_all_iocs(self) -> Dict[str, List[str]]:
        return {'ips': list(self._ips), 'domains': list(self._domains)}
