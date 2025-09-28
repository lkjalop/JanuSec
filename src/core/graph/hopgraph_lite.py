"""HopGraph-lite: ephemeral sliding window entity relationship context.

Captures relationships among (user, host, proc, ip) over a short time window to
emit context factors (burst, lateral movement candidate, sequence motifs).

This is intentionally lightweight; for scale-out, replace with dedicated graph store.
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Any, Set

class HopGraphLite:
    def __init__(self, window_seconds: int = 900, max_events: int = 5000):
        self.window_seconds = window_seconds
        self.max_events = max_events
        self.events: Deque[Tuple[float, Dict[str, Any]]] = deque()
        # Simple adjacency counts
        self.user_hosts: Dict[str, Set[str]] = defaultdict(set)
        self.host_users: Dict[str, Set[str]] = defaultdict(set)
        self.user_procs: Dict[str, Set[str]] = defaultdict(set)

    def _evict(self, now: float):
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            _, ev = self.events.popleft()
            u = ev.get('user')
            h = ev.get('host')
            p = ev.get('proc')
            if u and h and h in self.user_hosts[u]:
                # Lazy eviction; full cleanup not critical in lite version
                pass
        if len(self.events) > self.max_events:
            for _ in range(len(self.events) - self.max_events):
                self.events.popleft()

    def observe(self, event: Dict[str, Any]):
        now = time.time()
        self.events.append((now, event))
        u = event.get('user')
        h = event.get('host')
        p = event.get('proc') or event.get('process')
        if u and h:
            self.user_hosts[u].add(h)
            self.host_users[h].add(u)
        if u and p:
            self.user_procs[u].add(p)
        self._evict(now)

    def factors(self, event: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        u = event.get('user')
        h = event.get('host')
        # Burst: multiple distinct procs for same user in window
        if u and len(self.user_procs.get(u, [])) >= 5:
            out.append('graph_user_proc_burst')
        # Lateral movement candidate: user touching >1 distinct hosts quickly
        if u and len(self.user_hosts.get(u, [])) > 1:
            out.append('lateral_movement_candidate')
        # High fan-in host (many users)
        if h and len(self.host_users.get(h, [])) > 5:
            out.append('graph_host_multiuser_hotspot')
        return out

# Singleton or per-tenant instance can be managed externally.
_default_graph: HopGraphLite | None = None

def get_graph() -> HopGraphLite:
    global _default_graph
    if _default_graph is None:
        _default_graph = HopGraphLite()
    return _default_graph
