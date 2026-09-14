from __future__ import annotations

import os
import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional


class IngestionAnomalyDetector:
    """Lightweight ingestion anomaly detector with EWMA smoothing and gap persistence.

    This is intentionally minimal: record_event(source, ts) updates last_seen and ewma counts.
    detect_gaps returns sources with stale last_seen beyond threshold.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = Path(persist_dir or os.getenv('SESSION_PERSIST_DIR', 'data/sessions'))
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.ewma_path = self.persist_dir / 'ingestion_ewma.json'
        self.gaps_path = self.persist_dir / 'ingestion_gaps.json'
        self.alpha = float(os.getenv('INGESTION_EWMA_ALPHA', '0.6'))
        self.state: Dict[str, Any] = {'last_seen': {}, 'ewma_counts': {}}
        self._load()

    def _load(self):
        try:
            if self.ewma_path.exists():
                with open(self.ewma_path, 'r', encoding='utf-8') as f:
                    self.state = json.load(f) or self.state
        except Exception:
            pass

    def _save(self):
        try:
            # Atomic write to avoid partial files
            tmp = str(self.ewma_path) + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, ensure_ascii=False)
            try:
                Path(tmp).replace(self.ewma_path)
            except Exception:
                # fallback to os.replace
                import os as _os
                try:
                    _os.replace(tmp, str(self.ewma_path))
                except Exception:
                    pass
        except Exception:
            pass

    def record_event(self, source: str, ts: Optional[float] = None, tenant_id: Optional[str] = None) -> None:
        """Record an event seen from `source`. Optionally include `tenant_id` for multi-tenant contexts."""
        now = float(ts or time.time())
        key = source if not tenant_id else f"{tenant_id}::{source}"
        # update last_seen
        self.state.setdefault('last_seen', {})[key] = now
        # increment ewma count: treat each record as count=1 for demo
        prev = float(self.state.setdefault('ewma_counts', {}).get(key) or 0.0)
        new = self.alpha * 1.0 + (1.0 - self.alpha) * prev
        self.state['ewma_counts'][key] = new
        # persist atomically
        self._save()

    def last_event_received(self, source: Optional[str] = None) -> Dict[str, Any]:
        now = time.time()
        if source:
            # support direct key or tenant::source lookup
            ts = self.state.get('last_seen', {}).get(source)
            if ts is None:
                # search tenant-prefixed keys
                for k, v in (self.state.get('last_seen', {}) or {}).items():
                    if k.endswith(f"::{source}"):
                        ts = v
                        break
            return {'source': source, 'last_seen': ts, 'seconds_since': (now - ts) if ts else None}
        return {'last_seen_map': dict(self.state.get('last_seen', {}))}

    def detect_gaps(self, stale_threshold_seconds: int = 300) -> List[Dict[str, Any]]:
        now = time.time()
        gaps: List[Dict[str, Any]] = []
        for src, ts in (self.state.get('last_seen') or {}).items():
            try:
                if now - float(ts) > float(stale_threshold_seconds):
                    tenant = None
                    name = src
                    if '::' in str(src):
                        tenant, name = str(src).split('::', 1)
                    gaps.append({'source': name, 'raw_key': src, 'tenant': tenant, 'last_seen': ts, 'seconds_since': now - float(ts)})
            except Exception:
                continue
        # persist gaps for UI atomically
        try:
            tmp = str(self.gaps_path) + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump({'gaps': gaps, 'ts': now}, f)
            try:
                Path(tmp).replace(self.gaps_path)
            except Exception:
                import os as _os
                try:
                    _os.replace(tmp, str(self.gaps_path))
                except Exception:
                    pass
        except Exception:
            pass
        return gaps

    def get_summary(self) -> Dict[str, Any]:
        return {
            'last_seen': dict(self.state.get('last_seen', {})),
            'ewma_counts': dict(self.state.get('ewma_counts', {})),
        }


__all__ = ['IngestionAnomalyDetector']
