"""JA3 Novelty Lane

Flags TLS client JA3 hashes that are rare / new in the recent sliding window.
Heuristic approach (no ML):
 - Maintain frequency counts (LRU capped) of JA3 hashes
 - Mark 'ja3_novel' if first time seen after warm period
 - Mark 'ja3_rare' if count <= rare_threshold after warm period and total observations > warm_min
 - Optionally mark 'ja3_sudden_spike' if delta in last window > spike_ratio * historical average (placeholder)

Config (pipeline.hunt_lanes.ja3):
  rare_threshold (int, default 3)
  max_entries (int, default 5000)
  warm_min (int, default 20)  # don't emit until enough baseline

Metrics: lane_registry handles per-lane counts; gauge (later) can publish distinct JA3 seen.
"""
from __future__ import annotations
from typing import Dict, List
from collections import OrderedDict
try:
    from prometheus_client import Gauge  # type: ignore
except Exception:  # pragma: no cover
    Gauge = None  # type: ignore

class JA3NoveltyLane:
    name = 'ja3_novelty'

    def __init__(self, config):
        hl_cfg = config.get('pipeline', {}).get('hunt_lanes', {}).get('ja3', {}) if hasattr(config,'get') else {}
        self.rare_threshold = int(hl_cfg.get('rare_threshold', 3))
        self.max_entries = int(hl_cfg.get('max_entries', 5000))
        # Default warmup counts were tuned back down after replay failures showed
        # the previous bump to 50/30 prevented legitimate rare alerts from ever
        # emitting in smaller tenants. Falling back to the earlier heuristics keeps
        # the lane sensitive while still allowing operators to override via config.
        self.warm_min = int(hl_cfg.get('warm_min', 20))
        self.min_distinct_for_rare = int(hl_cfg.get('min_distinct_for_rare', 5))  # adaptive gating
        self.disable_rare = bool(hl_cfg.get('disable_rare', False))  # temp suppression switch
        self.freq: OrderedDict[str,int] = OrderedDict()
        self.total = 0
        # metrics
        if Gauge and not hasattr(self.__class__, '_g_init'):
            try:
                self.__class__.baseline_size_gauge = Gauge('ja3_baseline_size','Current JA3 frequency map size')
                self.__class__.distinct_ja3_gauge = Gauge('ja3_distinct_hashes','Distinct JA3 hashes observed')
                self.__class__._g_init = True
            except Exception:
                pass

    def _touch(self, ja3: str):
        if ja3 in self.freq:
            self.freq[ja3] += 1
            self.freq.move_to_end(ja3)
        else:
            self.freq[ja3] = 1
            if len(self.freq) > self.max_entries:
                self.freq.popitem(last=False)

    async def run(self, envelope, context):
        e = envelope.event
        ja3 = e.get('ja3_hash') or e.get('tls_ja3')
        if not ja3:
            return
        self.total += 1
        first_seen = ja3 not in self.freq
        self._touch(ja3)

        factors: List[str] = []
        if self.total >= self.warm_min:
            distinct = len(self.freq)
            if first_seen:
                factors.append('ja3_novel')
            if not self.disable_rare:
                threshold_distinct = min(self.min_distinct_for_rare, max(1, self.warm_min))
                if distinct >= threshold_distinct:
                    count = self.freq.get(ja3, 0)
                    if count <= self.rare_threshold:
                        factors.append('ja3_rare')
        if factors:
            envelope.add_emission(self.name, factors, notes=None, latency_ms=0.0)
        # update gauges best-effort
        try:
            if Gauge and hasattr(self.__class__, 'baseline_size_gauge'):
                self.__class__.baseline_size_gauge.set(len(self.freq))
            if Gauge and hasattr(self.__class__, 'distinct_ja3_gauge'):
                self.__class__.distinct_ja3_gauge.set(len(self.freq))
        except Exception:
            pass

# Factory helper
def build(config):
    return JA3NoveltyLane(config)
