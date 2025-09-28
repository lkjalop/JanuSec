"""Escalation queue with JSONL persistence (resilient across restarts).

Each escalation entry is appended to a JSONL file (append-only). On startup we
replay the file and keep only non-expired, open or unresolved items within TTL.
Resolved entries remain addressable for stats until TTL expiry.
"""
from __future__ import annotations
from typing import Dict, Any, List
import time, os, hashlib

class EscalationQueue:
    def __init__(self, ttl_seconds: int = 86400, path: str | None = None):
        self.ttl = ttl_seconds
        self.items: Dict[str, Dict[str, Any]] = {}
        self.path = path or 'artifacts/escalations/escalations.log'
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._loaded = False
        self._load()
        self._max_mb = float(os.getenv('LOG_MAX_MB','0'))

    def _maybe_rotate(self):
        if not self._max_mb or self._max_mb <= 0:
            return
        try:
            if not os.path.exists(self.path):
                return
            size_mb = os.path.getsize(self.path)/(1024*1024)
            if size_mb >= self._max_mb:
                base, ext = os.path.splitext(self.path)
                rotated = f"{base}.{int(time.time())}.log"
                os.rename(self.path, rotated)
        except Exception:
            pass

    def put(self, decision):
        rid = decision.event_id
        self.items[rid] = {
            'id': rid,
            'tenant_id': decision.tenant_id,
            'inserted_ts': time.time(),
            'severity': decision.severity,
            'quality': decision.quality,
            'factors': decision.factors,
            'reasons': decision.reasons,
            'status': 'open'
        }
        self._append_log({**self.items[rid], 'op':'put'})

    def list(self, tenant_id: str | None, include_resolved: bool = False, limit: int = 100):
        self._purge()
        rows = [v for v in self.items.values() if (tenant_id is None or v['tenant_id']==tenant_id)]
        if not include_resolved:
            rows = [r for r in rows if r['status']=='open']
        rows.sort(key=lambda r: r['inserted_ts'], reverse=True)
        return rows[:limit]

    def resolve(self, esc_id: str, verdict: str):
        row = self.items.get(esc_id)
        if not row:
            return False
        row['status'] = 'resolved'
        row['resolved_verdict'] = verdict
        row['resolved_ts'] = time.time()
        self._append_log({**row, 'op':'resolve'})
        return True

    def _purge(self):
        cutoff = time.time() - self.ttl
        for k in list(self.items.keys()):
            if self.items[k]['inserted_ts'] < cutoff:
                self.items.pop(k, None)

    # Persistence helpers
    def _append_log(self, obj: Dict[str, Any]):
        try:
            import json
            self._maybe_rotate()
            with open(self.path,'a',encoding='utf-8') as f:
                f.write(json.dumps(obj)+'\n')
        except Exception:
            pass

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        if not os.path.exists(self.path):
            return
        cutoff = time.time() - self.ttl
        try:
            import json
            with open(self.path,'r',encoding='utf-8') as f:
                for line in f:
                    line=line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    ins_ts = obj.get('inserted_ts',0)
                    if ins_ts < cutoff:
                        continue
                    rid = obj.get('id')
                    if not rid:
                        continue
                    existing = self.items.get(rid)
                    if not existing:
                        # Reconstruct minimal record
                        keep = {k: obj.get(k) for k in ('id','tenant_id','inserted_ts','severity','quality','factors','reasons','status','resolved_verdict','resolved_ts') if k in obj}
                        self.items[rid] = keep  # type: ignore
                    else:
                        # If resolve op arrives after put
                        if obj.get('status') == 'resolved':
                            existing.update(obj)
        except Exception:
            pass

    def stats(self, tenant_id: str | None):
        self._purge()
        now = time.time()
        rows = self.list(tenant_id, include_resolved=True, limit=100000)
        open_items = [r for r in rows if r['status']=='open']
        ages = [now - r['inserted_ts'] for r in open_items]
        import math
        p95_age = 0.0
        if ages:
            s = sorted(ages)
            idx = min(len(s)-1, int(len(s)*0.95)-1)
            p95_age = s[idx]
        return {
            'tenant_id': tenant_id,
            'open': len(open_items),
            'resolved': len([r for r in rows if r['status']=='resolved']),
            'p95_open_age_seconds': round(p95_age,2),
            'ttl_seconds': self.ttl
        }

_QUEUE: EscalationQueue | None = None

def get_escalation_queue() -> EscalationQueue:
    global _QUEUE
    if _QUEUE is None:
        ttl = int(os.getenv('ESCALATION_TTL_SECONDS','86400'))
        path = os.getenv('ESCALATION_LOG_PATH','artifacts/escalations/escalations.log')
        _QUEUE = EscalationQueue(ttl, path)
    return _QUEUE
