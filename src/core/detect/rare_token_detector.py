"""Rare Token Command Detector

Maintains token frequency distribution of command lines and emits:
 - cmd_rare_token_ratio (numeric factor via ratio threshold to be consumed later)
 - cmd_rare_token_spike (discrete factor if ratio exceeds threshold)
"""
from __future__ import annotations
from collections import Counter, deque
from typing import Dict, List
import re, threading, math, json, os, hashlib, hmac, time

TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{4,}")

class RareTokenModel:
    """Per-tenant rare token frequency tracker.

    Persists each tenant's token freq distribution under:
      artifacts/state/tenants/<tenant>/rare_tokens.json
    """
    def __init__(self, max_tokens: int = 50000, min_count_promote: int = 3, ttl_observations: int = 2_000_000, base_dir: str = 'artifacts/state/tenants'):
        self._lock = threading.Lock()
        self._max = max_tokens
        self._min = min_count_promote
        self._ttl_observations = ttl_observations
        self._base_dir = base_dir
        # tenant -> Counter + total observed tokens
        self._freq: Dict[str, Counter[str]] = {}
        self._total: Dict[str, int] = {}
        self._dirty: set[str] = set()
        self._load_all()

    def _tenant_path(self, tenant: str) -> str:
        return os.path.join(self._base_dir, tenant, 'rare_tokens.json')

    def observe(self, tenant: str, cmdline: str) -> Dict[str,float | int]:
        tenant = tenant or 'default'
        tokens = TOKEN_RE.findall(cmdline.lower())
        rare = 0
        with self._lock:
            freq = self._freq.setdefault(tenant, Counter())
            total = self._total.setdefault(tenant, 0)
            for t in tokens:
                if freq[t] < self._min:
                    rare += 1
                freq[t] += 1
                total += 1
            # Enforce caps
            if len(freq) > self._max or total > self._ttl_observations:
                freq_sorted = freq.most_common()
                cutoff_index = int(len(freq_sorted)*0.8)
                for tok,_ in freq_sorted[cutoff_index:]:
                    del freq[tok]
                if total > self._ttl_observations:
                    for tok in list(freq.keys()):
                        freq[tok] = max(1, int(freq[tok]*0.5))
                    total = sum(freq.values())
                self._total[tenant] = total
            self._dirty.add(tenant)
        ratio = (rare / max(1,len(tokens))) if tokens else 0.0
        return {'rare_ratio': ratio, 'token_count': len(tokens), 'rare_count': rare}

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
                    freq_map = {k:int(v) for k,v in data.get('freq',{}).items()}
                    self._freq[tenant] = Counter(freq_map)
                    self._total[tenant] = int(data.get('total',0))
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
                payload = {
                    'freq': {k:int(v) for k,v in self._freq.get(tenant, {}).items()},
                    'total': self._total.get(tenant,0),
                    'saved_at': time.time()
                }
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

_rare_singleton: RareTokenModel | None = None

def get_rare_token_model() -> RareTokenModel:
    global _rare_singleton
    if _rare_singleton is None:
        _rare_singleton = RareTokenModel()
    return _rare_singleton
