"""Authentication failure burst detector.

Maintains a sliding window of recent auth failure events per user and emits a
factor when failures exceed a threshold within the window.
"""
from __future__ import annotations
import time
from collections import deque, defaultdict
from typing import Deque, Dict, List, Tuple, Any

class AuthBurstDetector:
    def __init__(self, window_seconds: int = 300, threshold: int = 5, max_events: int = 5000):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.max_events = max_events
        self.events: Deque[Tuple[float, str]] = deque()  # (ts, user)
        self.user_counts: Dict[str, int] = defaultdict(int)

    def observe(self, event: Dict[str, Any]):
        user = event.get('user') or event.get('username')
        if not user:
            return
        # Consider event as failure if explicit flag or type
        details = event.get('details') or {}
        is_fail = False
        if details.get('auth') == 'fail':
            is_fail = True
        elif event.get('event_type') in ('auth_fail','login_failed'):
            is_fail = True
        if not is_fail:
            return
        now = time.time()
        self.events.append((now, user))
        self.user_counts[user] += 1
        self._evict(now)

    def _evict(self, now: float):
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            _, u = self.events.popleft()
            self.user_counts[u] -= 1
            if self.user_counts[u] <= 0:
                self.user_counts.pop(u, None)
        if len(self.events) > self.max_events:
            for _ in range(len(self.events) - self.max_events):
                _, u2 = self.events.popleft()
                self.user_counts[u2] -= 1
                if self.user_counts[u2] <= 0:
                    self.user_counts.pop(u2, None)

    def factors(self, event: Dict[str, Any]) -> List[str]:
        user = event.get('user') or event.get('username')
        if user and self.user_counts.get(user, 0) >= self.threshold:
            return ['auth_fail_burst_5m']
        return []

_default: AuthBurstDetector | None = None

def get_auth_burst_detector() -> AuthBurstDetector:
    global _default
    if _default is None:
        _default = AuthBurstDetector()
    return _default

def auth_burst_factors(event: Dict[str, Any]) -> List[str]:
    det = get_auth_burst_detector()
    # Observe first so current event contributes
    det.observe(event)
    return det.factors(event)

__all__ = ['auth_burst_factors','get_auth_burst_detector','AuthBurstDetector']
