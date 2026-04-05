from __future__ import annotations
import os, time, hashlib, threading
from typing import Dict, Set, List, Tuple
from .annotations import emit_edge
from src.core.factors.observe_flags import adjust_delta
from src.core.threat_modeling.ingestion_normalizer import normalize_factors

class CampaignCorrelator:
    """Identifies cross-incident / cross-entity campaigns via rare shared pivots.

    Pivots: configurable factor prefixes or entity keys (JA3, rare domain factors, high-risk ASN factors, beacon JA3 etc.).
    Maintains: pivot -> set(incident_ids) with timestamps for sliding window pruning.
    Emits: campaign factor 'campaign:cluster' once per pivot crossing threshold.
    Edge annotation recorded for explainability & future ML.
    """

    def __init__(self):
        self.enabled = os.getenv('CAMPAIGNS_ENABLED','1') not in ('0','false','False')
        self.min_incidents = int(os.getenv('CAMPAIGN_MIN_INCIDENTS','3') or 3)
        self.window_seconds = int(os.getenv('CAMPAIGN_WINDOW_SECONDS','7200') or 7200)
        self.max_pivots = int(os.getenv('CAMPAIGN_MAX_PIVOTS','10000') or 10000)
        # pivot -> { incident_id: last_seen_ts }
        self._pivots: Dict[str, Dict[str,float]] = {}
        self._lock = threading.RLock()
        # Factor prefixes considered as potential pivots
        default_prefixes = 'ssl:ja3_known_bad,ssl:ja3_rare,net:beacon_periodic,net:asn_high_risk,net:country_rare'
        self.pivot_factor_prefixes = {p.strip() for p in os.getenv('CAMPAIGN_PIVOT_PREFIXES', default_prefixes).split(',') if p.strip()}
        # Track which pivot already emitted campaign factor recently (cooldown)
        self.cooldown = int(os.getenv('CAMPAIGN_COOLDOWN_SECONDS','1800') or 1800)
        self._last_emit: Dict[str,float] = {}

    def _prune(self, now: float):
        cutoff = now - self.window_seconds
        for pivot in list(self._pivots.keys()):
            inner = self._pivots[pivot]
            for inc, ts in list(inner.items()):
                if ts < cutoff:
                    inner.pop(inc, None)
            if not inner:
                self._pivots.pop(pivot, None)
        # Also prune old last_emit entries
        for p,t in list(self._last_emit.items()):
            if t < cutoff:
                self._last_emit.pop(p, None)

    def ingest(self, event: dict, factors: List[str]) -> Tuple[List[str], float]:
        if not self.enabled or not factors:
            return [], 0.0
        incident_id = str(event.get('incident_id') or event.get('incident') or '')
        if not incident_id:
            return [], 0.0  # Need incident context to aggregate
        now = time.time()
        with self._lock:
            self._prune(now)
            emitted: List[str] = []
            delta_total = 0.0
            for f in normalize_factors(factors):
                # Check pivot prefixes
                if not any(f.startswith(pref) for pref in self.pivot_factor_prefixes):
                    continue
                # Derive pivot key (could add normalization later)
                pivot = f
                if pivot not in self._pivots:
                    if len(self._pivots) >= self.max_pivots:
                        continue
                    self._pivots[pivot] = {}
                self._pivots[pivot][incident_id] = now
                active_incidents = len(self._pivots[pivot])
                if active_incidents >= self.min_incidents:
                    last = self._last_emit.get(pivot)
                    if last and (now - last) < self.cooldown:
                        continue
                    self._last_emit[pivot] = now
                    # Stable short hash for pivot -> campaign factor identity
                    h = hashlib.sha1(pivot.encode('utf-8')).hexdigest()[:8]
                    campaign_factor = f'campaign:{h}'
                    if campaign_factor not in emitted and campaign_factor not in factors:
                        emitted.append(campaign_factor)
                        # Modest, bounded delta
                        delta = adjust_delta('campaign', 0.02)
                        delta_total += delta
                        emit_edge({
                            'edge_type': 'campaign',
                            'rule_id': 'campaign_pivot_threshold',
                            'ts': now,
                            'entities': [incident_id],
                            'input_factors': [f],
                            'output_factor': campaign_factor,
                            'delta': delta,
                            'meta': {
                                'pivot': pivot,
                                'active_incidents': active_incidents,
                                'window_seconds': self.window_seconds
                            }
                        })
            return emitted, delta_total

GLOBAL_CAMPAIGN_CORRELATOR = CampaignCorrelator()

def record_campaign_correlation(event: dict, factors: List[str]):
    try:
        return GLOBAL_CAMPAIGN_CORRELATOR.ingest(event, factors)
    except Exception:
        return [], 0.0

__all__ = ['CampaignCorrelator','GLOBAL_CAMPAIGN_CORRELATOR','record_campaign_correlation']