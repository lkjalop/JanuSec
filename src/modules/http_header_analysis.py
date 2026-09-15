"""HTTP Header / Method Analysis Module (Stub Phase 1)

Emits factors for unusual HTTP methods, suspicious headers, malformed or suspect user agents.
Factors:
 - http:method_rare
 - http:header_injection_pattern
 - http:user_agent_suspect

Feature flag: HTTP_HEADER_ANALYSIS_ENABLED (default disabled)
Confidence capped at 0.08.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List

RARE_METHODS = {"TRACE","TRACK","DEBUG","CONNECT"}
INJECTION_HEADER_PATTERN = re.compile(r"(;\s*(bash|sh|cmd|powershell|/bin/sh))|(&&)|(`)|\$\(\w+\)", re.IGNORECASE)
MIN_UA_LENGTH = 5

class HTTPHeaderAnalysis:
    MAX_DELTA = 0.08
    def __init__(self, config):
        self.config = config
        self.enabled = os.getenv('HTTP_HEADER_ANALYSIS_ENABLED','0').lower() in {'1','true','yes'}

    async def analyze_event(self, event: dict[str,Any]) -> dict[str,Any]:
        if not self.enabled:
            return {'factors': [], 'confidence_delta': 0.0}
        factors: list[str] = []
        delta = 0.0
        method = (event.get('http_method') or event.get('method') or '').upper()
        if method in RARE_METHODS:
            factors.append('http:method_rare'); delta += 0.03
        headers = event.get('http_headers') or event.get('headers') or {}
        if isinstance(headers, dict):
            for _k,v in list(headers.items())[:20]:
                if isinstance(v,str) and INJECTION_HEADER_PATTERN.search(v):
                    factors.append('http:header_injection_pattern'); delta += 0.04
                    break
        ua = event.get('http_user_agent') or event.get('user_agent')
        if isinstance(ua,str):
            uan = ua.strip()
            if len(uan) < MIN_UA_LENGTH or 'curl/' in uan.lower() or uan.lower() in {'python-requests','wget'}:
                factors.append('http:user_agent_suspect'); delta += 0.03
        if delta > self.MAX_DELTA:
            delta = self.MAX_DELTA
        return {'factors': factors, 'confidence_delta': round(delta,4)}

__all__ = ['HTTPHeaderAnalysis']
