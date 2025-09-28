"""Egress EWMA Tracker

Tracks per-host outbound bytes with EWMA + variance to emit egress_volume_spike.
"""
from __future__ import annotations
from typing import Dict, Tuple
import threading, time, math, json, os, hashlib

class EgressEWMA:
    """Per-tenant EWMA egress spike tracker.

    Persists each tenant's state under artifacts/state/tenants/<tenant>/egress_ewma.json
    """
    def __init__(self, alpha: float = 0.3, k: float = 3.0, base_dir: str = 'artifacts/state/tenants'):
        self.alpha = alpha
        self.k = k
        self._lock = threading.Lock()
        # tenant -> host -> (ewma, ewvar, last_ts)
        self._state: Dict[str, Dict[str, Tuple[float,float,float]]] = {}
        self._dirty: set[str] = set()
        self._base_dir = base_dir
        self._load_all()

    def _tenant_path(self, tenant: str) -> str:
        return os.path.join(self._base_dir, tenant, 'egress_ewma.json')

    def observe(self, tenant: str, host: str, bytes_out: float, ts: float | None = None) -> bool:
        tenant = tenant or 'default'
        now = ts or time.time()
        with self._lock:
            tmap = self._state.setdefault(tenant, {})
            ewma, ewvar, _ = tmap.get(host, (bytes_out, 0.0, now))
            prev = ewma
            ewma = self.alpha * bytes_out + (1-self.alpha) * ewma
            ewvar = (1-self.alpha) * (ewvar + self.alpha * (bytes_out - prev)**2)
            tmap[host] = (ewma, ewvar, now)
            std = math.sqrt(max(0.0, ewvar))
            threshold = ewma + self.k * std
            spike = std > 0 and bytes_out > threshold
            self._dirty.add(tenant)
            return spike

    def _load_all(self):
        try:
            if not os.path.exists(self._base_dir):
                return
            for tenant in os.listdir(self._base_dir):
                path = self._tenant_path(tenant)
                if not os.path.exists(path):
                    continue
                try:
                    with open(path,'r',encoding='utf-8') as f:
                        wrapper = json.load(f)
                    data = wrapper.get('payload', wrapper)
                    expected = wrapper.get('sha256')
                    raw = json.dumps(data, sort_keys=True).encode('utf-8')
                    calc = hashlib.sha256(raw).hexdigest()
                    if expected and calc != expected:
                        continue
                    state_map = {}
                    for host, triple in data.get('state', {}).items():
                        state_map[host] = tuple(triple)  # type: ignore
                    if state_map:
                        self._state[tenant] = state_map
                except Exception:
                    continue
        except Exception:
            pass

    def _save(self):
        if not self._dirty:
            return
        for tenant in list(self._dirty):
            try:
                path = self._tenant_path(tenant)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                payload = {'state': self._state.get(tenant, {}), 'saved_at': time.time()}
                raw = json.dumps(payload, sort_keys=True).encode('utf-8')
                digest = hashlib.sha256(raw).hexdigest()
                with open(path,'w',encoding='utf-8') as f:
                    json.dump({'payload': payload, 'sha256': digest}, f)
                self._dirty.discard(tenant)
            except Exception:
                pass

    def flush(self):
        with self._lock:
            self._save()

_egress_singleton: EgressEWMA | None = None

def get_egress_tracker() -> EgressEWMA:
    global _egress_singleton
    if _egress_singleton is None:
        _egress_singleton = EgressEWMA()
    return _egress_singleton
