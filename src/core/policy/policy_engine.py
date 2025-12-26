"""Policy Engine (Allow / Block / Benign Heuristics)

Loads JSON config from env `POLICY_CONFIG_JSON` (or empty) and exposes
is_allow / is_block checks. Matching is case-insensitive. Wildcard * only
at beginning or end of pattern for domains/processes (simple contains/startswith).
"""
from __future__ import annotations

import functools
import json
import os
import re
import time
from collections.abc import Callable
from typing import Any, Dict, List


def _load_config() -> dict[str, Any]:
    blob = os.getenv('POLICY_CONFIG_JSON')
    if not blob:
        return {'allow':{},'block':{}}
    try:
        return json.loads(blob)
    except Exception:
        return {'allow':{},'block':{}}

class PolicyEngine:
    """Policy evaluation with lightweight caching & wildcard support.

    Domain pattern semantics:
      - '*.example.com' matches any subdomain depth of example.com
      - 'dev.*.corp.local' converts * to '.*' regex (greedy)
      - '?" matches single character where used (converted to regex '.')
      - Plain string => exact match (case-insensitive)
    Command regex list is block-only for now; allow substrings for allow-list.
    """
    def __init__(self):
        self._cache: dict[str, tuple[float, str]] = {}
        self._cache_ttl = 300  # seconds
        self._cache_max = 1024
        self.reload()

    def reload(self):
        cfg = _load_config()
        self.allow = cfg.get('allow',{}) or {}
        self.block = cfg.get('block',{}) or {}
        self._compile(); self._cache.clear()

    def _compile(self):
        self._block_domain_patterns = [self._compile_pattern(p) for p in self.block.get('domains',[]) if isinstance(p,str)]
        self._allow_domain_patterns = [self._compile_pattern(p) for p in self.allow.get('domains',[]) if isinstance(p,str)]
        self._block_proc = set(p.lower() for p in self.block.get('process_names',[]) if isinstance(p,str))
        self._allow_proc = set(p.lower() for p in self.allow.get('process_names',[]) if isinstance(p,str))
        self._block_cmd_regex = []
        for r in self.block.get('command_regex',[]) if isinstance(self.block.get('command_regex',[]), list) else []:
            if isinstance(r,str):
                try:
                    self._block_cmd_regex.append(re.compile(r, re.IGNORECASE))
                except Exception:
                    continue
        self._allow_cmd_sub = [s.lower() for s in self.allow.get('command_substrings',[]) if isinstance(s,str)]

    def _cache_set(self, key: str, val: str):
        if len(self._cache) >= self._cache_max:
            # Remove ~10% oldest
            for k in list(self._cache.keys())[: int(self._cache_max*0.1)]:
                self._cache.pop(k, None)
        self._cache[key] = (time.time(), val)

    def _cache_get(self, key: str) -> str | None:
        item = self._cache.get(key)
        if not item:
            return None
        ts, val = item
        if time.time() - ts > self._cache_ttl:
            self._cache.pop(key, None)
            return None
        return val

    def _compile_pattern(self, patt: str) -> Callable[[str], bool]:
        raw = patt.lower()
        # Replace shell wildcards with regex equivalents
        expr = '^' + re.escape(raw).replace('\\*','.*').replace('\\?','.') + '$'
        cre = re.compile(expr)
        return lambda v, c=cre: bool(c.match(v.lower()))

    def evaluate(self, ev: dict[str, Any]) -> str | None:
        """Return 'block', 'allow', or None (undecided) with cache."""
        key = f"{ev.get('tenant_id')}|{ev.get('domain')}|{ev.get('process_name')}|{ev.get('command_line')}"
        cached = self._cache_get(key)
        if cached:
            return cached if cached != 'none' else None
        verdict = None
        dom = (ev.get('domain') or '').lower()
        if dom and any(fn(dom) for fn in self._block_domain_patterns):
            verdict = 'block'
        if verdict is None:
            proc = (ev.get('process_name') or '').lower()
            if proc in self._block_proc:
                verdict = 'block'
        if verdict is None:
            cmd = (ev.get('command_line') or '').lower()
            for rgx in self._block_cmd_regex:
                try:
                    if rgx and rgx.search(cmd):
                        verdict = 'block'; break
                except Exception:
                    continue
        # Allow list only considered if not blocked
        if verdict is None and dom and any(fn(dom) for fn in self._allow_domain_patterns):
            verdict = 'allow'
        if verdict is None:
            proc = (ev.get('process_name') or '').lower()
            if proc in self._allow_proc:
                verdict = 'allow'
        if verdict is None:
            cmd = (ev.get('command_line') or '').lower()
            for sub in self._allow_cmd_sub:
                if sub in cmd:
                    verdict = 'allow'; break
        self._cache_set(key, verdict or 'none')
        return verdict

    # Backwards compatibility helper
    def is_block(self, ev: dict[str, Any]) -> bool:
        return self.evaluate(ev) == 'block'

    def is_allow(self, ev: dict[str, Any]) -> bool:
        return self.evaluate(ev) == 'allow'

_ENGINE: PolicyEngine | None = None

def get_policy_engine() -> PolicyEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PolicyEngine()
    return _ENGINE
