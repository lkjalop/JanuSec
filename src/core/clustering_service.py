from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.metrics.registry import metric_counter, metric_histogram

# Metrics (registered via the registry helper so expected_metrics() picks them up)
_ALERT_CLUSTERS_TOTAL = metric_counter('alerts', 'clusters', 'Total alert clusters created')
_ALERT_CLUSTER_SIZE_HIST = metric_histogram('alerts', 'cluster_size_histogram', 'Alert cluster sizes')


@dataclass
class ClusterRecord:
    cluster_id: str
    size: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    sample_event_ids: List[str] = field(default_factory=list)


class ClusteringService:
    """In-memory alert clustering service.

    A lightweight, async-friendly service that groups alerts by a signature
    (derived externally or by caller). It keeps minimal state per-cluster and
    supports a time-windowed duplicate detection.
    """

    def __init__(self, window_seconds: int = 300, max_samples: int = 8, ttl_seconds: Optional[int] = None):
        self.window_seconds = int(window_seconds)
        self.max_samples = int(max_samples)
        # TTL for cluster removal (if None, use window_seconds*4)
        self.ttl_seconds = int(ttl_seconds) if ttl_seconds is not None else (self.window_seconds * 4)
        self._clusters: Dict[str, ClusterRecord] = {}
        self._lock = asyncio.Lock()
        self._update_counter = 0
        # background eviction task handle (managed via explicit start/stop)
        self._evict_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Start background eviction loop if not already running."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running() and self._evict_task is None:
                self._evict_task = loop.create_task(self._eviction_loop())
        except Exception:
            pass

    def stop(self) -> None:
        """Cancel background eviction loop if running."""
        try:
            if self._evict_task is not None:
                self._evict_task.cancel()
                self._evict_task = None
        except Exception:
            pass

    async def _eviction_loop(self):
        while True:
            await asyncio.sleep(max(1, min(30, self.window_seconds)))
            now = time.time()
            cutoff = now - self.ttl_seconds
            async with self._lock:
                old = [cid for cid, rec in self._clusters.items() if rec.last_ts < cutoff]
                for cid in old:
                    try:
                        del self._clusters[cid]
                    except KeyError:
                        pass

    async def update(self, cluster_id: str, event_id: str, ts: Optional[float] = None, raw_signature: Optional[str] = None, contributors: Optional[Dict] = None) -> Dict:
        """Register an event into cluster identified by `cluster_id`.

        Returns a dict with cluster metadata and `is_duplicate` indicating whether
        the event shares the cluster with a previous event within the window.
        """
        now = float(ts or time.time())
        async with self._lock:
            self._update_counter += 1
            # Lazy eviction every 256 updates (additional safety)
            if self._update_counter % 256 == 0:
                cutoff = now - self.ttl_seconds
                old = [cid for cid, rec in self._clusters.items() if rec.last_ts < cutoff]
                for cid in old:
                    try:
                        del self._clusters[cid]
                    except KeyError:
                        pass

            rec = self._clusters.get(cluster_id)
            is_new = rec is None
            if is_new:
                rec = ClusterRecord(cluster_id=cluster_id, size=1, first_ts=now, last_ts=now, sample_event_ids=[event_id])
                # store explainability fields
                if raw_signature:
                    setattr(rec, 'raw_signature', raw_signature)
                if contributors:
                    setattr(rec, 'contributors', contributors)
                self._clusters[cluster_id] = rec
                try:
                    _ALERT_CLUSTERS_TOTAL.inc()
                except Exception:
                    pass
                is_duplicate = False
            else:
                prev_last = rec.last_ts
                rec.size += 1
                rec.last_ts = now
                # Maintain bounded sample list (prepend newest)
                rec.sample_event_ids.insert(0, event_id)
                if len(rec.sample_event_ids) > self.max_samples:
                    rec.sample_event_ids = rec.sample_event_ids[: self.max_samples]
                # Duplicate if previous event within window
                is_duplicate = (now - prev_last) <= self.window_seconds

            try:
                _ALERT_CLUSTER_SIZE_HIST.observe(float(rec.size))
            except Exception:
                pass

            novelty = 1.0 / rec.size if rec.size else 1.0
            out = {
                'cluster_id': rec.cluster_id,
                'size': rec.size,
                'first_ts': rec.first_ts,
                'last_ts': rec.last_ts,
                'sample_event_ids': list(rec.sample_event_ids),
                'is_duplicate': is_duplicate,
                'novelty_score': novelty,
            }
            # attach explainability if present
            if hasattr(rec, 'raw_signature'):
                out['raw_signature'] = getattr(rec, 'raw_signature')
            if hasattr(rec, 'contributors'):
                out['contributors'] = getattr(rec, 'contributors')
            return out

    async def get(self, cluster_id: str) -> Optional[Dict]:
        async with self._lock:
            rec = self._clusters.get(cluster_id)
            if not rec:
                return None
            out = {
                'cluster_id': rec.cluster_id,
                'size': rec.size,
                'first_ts': rec.first_ts,
                'last_ts': rec.last_ts,
                'sample_event_ids': list(rec.sample_event_ids),
                'novelty_score': 1.0 / rec.size if rec.size else 1.0,
            }
            if hasattr(rec, 'raw_signature'):
                out['raw_signature'] = getattr(rec, 'raw_signature')
            if hasattr(rec, 'contributors'):
                out['contributors'] = getattr(rec, 'contributors')
            return out

    async def size(self) -> int:
        async with self._lock:
            return len(self._clusters)


# Singleton instance used by the application
CLUSTERING = ClusteringService()
