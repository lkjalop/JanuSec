"""Domain Novelty Tracker
Tracks first-seen timestamps per domain and emits new_domain_seen for recent first observation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from typing import Dict


class DomainTracker:
    """Per-tenant domain novelty tracker with partitioned persistence.

    Stores first-seen timestamps per domain per tenant under:
      artifacts/state/tenants/<tenant>/domain_tracker.json
    """
    def __init__(self, novelty_window_s: float = 3600, ttl_s: float = 86400, max_domains: int = 50000, base_dir: str = 'artifacts/state/tenants'):
        self.novelty_window_s = novelty_window_s
        self.ttl_s = ttl_s
        self.max_domains = max_domains
        self._lock = threading.Lock()
        self._base_dir = base_dir
        # tenant -> {domain: ts}
        self._first_seen: dict[str, dict[str,float]] = {}
        self._dirty: set[str] = set()
        self._load_all()

    def _tenant_path(self, tenant: str) -> str:
        return os.path.join(self._base_dir, tenant, 'domain_tracker.json')

    def observe(self, tenant: str, domain: str) -> bool:
        tenant = tenant or 'default'
        now = time.time(); key = domain.lower()
        with self._lock:
            tmap = self._first_seen.setdefault(tenant, {})
            max_entries = os.getenv('MAX_DOMAIN_TRACK_ENTRIES_PER_TENANT')
            try:
                max_entries_val = int(max_entries) if max_entries else 0
            except Exception:
                max_entries_val = 0
            if len(tmap) > self.max_domains:
                items = sorted(tmap.items(), key=lambda x: x[1])
                for k,_ in items[: max(1, len(items)//20)]:
                    tmap.pop(k, None)
            if max_entries_val and len(tmap) >= max_entries_val and key not in tmap:
                # Quota reached; do not learn new domain (treat as not new to avoid data skew)
                return False
            first = tmap.get(key)
            if first is None:
                tmap[key] = now; self._dirty.add(tenant); return True
            if (now - first) > self.ttl_s:
                tmap[key] = now; self._dirty.add(tenant); return True
            return (now - first) <= self.novelty_window_s

    def observe_legacy(self, domain: str) -> bool:
        return self.observe('default', domain)

    def _load_all(self):
        try:
            if not os.path.exists(self._base_dir):
                return
            for tenant in os.listdir(self._base_dir):
                path = self._tenant_path(tenant)
                if not os.path.exists(path):
                    continue
                try:
                    with open(path,encoding='utf-8') as f:
                        wrapper = json.load(f)
                    data = wrapper.get('payload', wrapper)
                    raw = json.dumps(data, sort_keys=True).encode('utf-8')
                    expected_sha = wrapper.get('sha256')
                    expected_hmac = wrapper.get('hmac')
                    calc_sha = hashlib.sha256(raw).hexdigest()
                    key = os.getenv('STATE_HMAC_KEY')
                    if key:
                        calc_hmac = hmac.new(key.encode('utf-8'), raw, hashlib.sha256).hexdigest()
                        if expected_hmac and calc_hmac != expected_hmac:
                            continue
                    elif expected_sha and calc_sha != expected_sha:
                        continue
                    first_map = {k: float(v) for k,v in data.get('first_seen',{}).items()}
                    if first_map:
                        self._first_seen[tenant] = first_map
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
                payload = {'first_seen': self._first_seen.get(tenant, {}), 'saved_at': time.time()}
                raw = json.dumps(payload, sort_keys=True).encode('utf-8')
                digest = hashlib.sha256(raw).hexdigest()
                record = {'payload': payload, 'sha256': digest}
                key = os.getenv('STATE_HMAC_KEY')
                if key:
                    record['hmac'] = hmac.new(key.encode('utf-8'), raw, hashlib.sha256).hexdigest()
                with open(path,'w',encoding='utf-8') as f:
                    json.dump(record, f)
                self._dirty.discard(tenant)
            except Exception:
                pass

    def flush(self):
        with self._lock:
            self._save()

_domain_tracker_singleton: DomainTracker | None = None

def get_domain_tracker() -> DomainTracker:
    global _domain_tracker_singleton
    if _domain_tracker_singleton is None:
        _domain_tracker_singleton = DomainTracker()
    return _domain_tracker_singleton
