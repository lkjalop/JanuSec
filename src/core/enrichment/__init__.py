"""Core enrichment helpers.

Exports ENRICHMENT (an EnrichmentService instance) and DKIM helpers.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from .dkim_history import get_last_dkim, record_dkim_result

try:
    from core.metrics.registry import metric_counter, metric_histogram, metric_gauge
    _ENRICH_CHECKS  = metric_counter  ('enrichment', 'checks',                'Total enrichment checks')
    _ENRICH_INCOMPLETE = metric_counter('enrichment', 'incomplete_total',      'Total incomplete enrichment observations')
    _ENRICH_HIST    = metric_histogram('enrichment', 'completeness_histogram', 'Enrichment completeness')
    _ENRICH_GAUGE   = metric_gauge    ('enrichment', 'completeness',           'Enrichment completeness per tenant', labels=['tenant_id'])
except Exception:
    class _Noop:  # noqa: E303
        def inc(self): pass
        def observe(self, v): pass
        def set(self, v): pass
        def labels(self, *a, **kw): return self
    _ENRICH_CHECKS = _ENRICH_INCOMPLETE = _ENRICH_HIST = _ENRICH_GAUGE = _Noop()  # type: ignore


def _get_nested(event: Dict[str, Any], path: str) -> Any:
    cur = event
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class EnrichmentService:
    def __init__(self):
        raw = os.getenv('ENRICH_REQUIRED_FIELDS', '')
        self.required = [p.strip() for p in raw.split(',') if p.strip()]
        self.field_weights = self._load_weights(os.getenv('ENRICH_FIELD_WEIGHTS', ''))

    def _load_weights(self, raw: str) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for part in [p.strip() for p in raw.split(',') if p.strip()]:
            if ':' in part:
                k, v = part.split(':', 1)
                try:
                    out[k.strip()] = float(v)
                except Exception:
                    out[k.strip()] = 1.0
            else:
                out[part] = 1.0
        return out

    def refresh(self):
        raw = os.getenv('ENRICH_REQUIRED_FIELDS', '')
        self.required = [p.strip() for p in raw.split(',') if p.strip()]
        self.field_weights = self._load_weights(os.getenv('ENRICH_FIELD_WEIGHTS', ''))

    def completeness(self, event: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
        try:
            _ENRICH_CHECKS.inc()
        except Exception:
            pass
        # Allow per-tenant override
        if tenant_id:
            tkey = f'ENRICH_REQUIRED_FIELDS_{tenant_id.upper().replace("-","_").replace(".","_")}'
            override = os.getenv(tkey)
            reqs = [p.strip() for p in override.split(',') if p.strip()] if override is not None else list(self.required)
        else:
            reqs = list(self.required)
        # Refresh required fields from env on every call (tests may change env)
        if not reqs:
            raw = os.getenv('ENRICH_REQUIRED_FIELDS', '')
            reqs = [p.strip() for p in raw.split(',') if p.strip()]

        weights = dict(self.field_weights)
        if tenant_id:
            wkey = f'ENRICH_FIELD_WEIGHTS_{tenant_id.upper().replace("-","_").replace(".","_")}'
            woverride = os.getenv(wkey)
            if woverride is not None:
                weights.update(self._load_weights(woverride))

        total_weight = 0.0
        present_weight = 0.0
        missing: List[str] = []
        for p in reqs:
            w = float(weights.get(p, 1.0))
            total_weight += w
            val = _get_nested(event, p)
            if val is None or (isinstance(val, str) and not val.strip()):
                missing.append(p)
            else:
                present_weight += w

        completeness = (present_weight / total_weight) if total_weight else 1.0
        try:
            _ENRICH_HIST.observe(completeness)
        except Exception:
            pass
        if missing:
            try:
                _ENRICH_INCOMPLETE.inc()
            except Exception:
                pass
        return {
            'required_count': len(reqs),
            'present_count': len(reqs) - len(missing),
            'required_weight': total_weight,
            'present_weight': present_weight,
            'completeness': completeness,
            'missing': missing,
        }


# Singleton used by src.api.server and other importers
ENRICHMENT = EnrichmentService()

__all__ = ['get_last_dkim', 'record_dkim_result', 'ENRICHMENT', 'EnrichmentService']
