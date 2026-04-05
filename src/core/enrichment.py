from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from core.metrics.registry import metric_counter, metric_histogram, metric_gauge

# Metrics
_ENRICH_CHECKS = metric_counter('enrichment', 'checks', 'Total enrichment checks')
_ENRICH_INCOMPLETE = metric_counter('enrichment', 'incomplete_total', 'Total incomplete enrichment observations')
_ENRICH_HIST = metric_histogram('enrichment', 'completeness_histogram', 'Enrichment completeness')
_ENRICH_GAUGE = metric_gauge('enrichment', 'completeness', 'Enrichment completeness per tenant', labels=['tenant_id'])


def _get_nested(event: Dict[str, Any], path: str) -> Any:
    """Support dotted path like 'details.ip' to extract nested value."""
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
        # Field weights: comma-separated name:weight
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
        """Return completeness info and metrics for event.

        Returns: {required_count, present_count, completeness (0-1), missing: [paths]}
        """
        _ENRICH_CHECKS.inc()
        # Allow per-tenant override of required fields via env ENRICH_REQUIRED_FIELDS_<TENANT>
        if tenant_id:
            tkey = f'ENRICH_REQUIRED_FIELDS_{tenant_id.upper().replace("-","_").replace(".","_")}'
            override = os.getenv(tkey)
            if override is not None:
                reqs = [p.strip() for p in override.split(',') if p.strip()]
            else:
                reqs = list(self.required)
        else:
            reqs = list(self.required)

        # Field weights (per-tenant override supported via ENRICH_FIELD_WEIGHTS_<TENANT>)
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
            w = weights.get(p, 1.0)
            total_weight += float(w)
            val = _get_nested(event, p)
            if val is None or (isinstance(val, str) and not val.strip()):
                missing.append(p)
            else:
                present_weight += float(w)

        completeness = (present_weight / total_weight) if total_weight else 1.0
        try:
            _ENRICH_HIST.observe(completeness)
        except Exception:
            pass
        if missing:
            _ENRICH_INCOMPLETE.inc()
        try:
            # Record per-tenant completeness gauge
            tenant_label = tenant_id or os.getenv('DEFAULT_TENANT', 'default')
            try:
                _ENRICH_GAUGE.labels(tenant_label).set(float(completeness))
            except Exception:
                # Some Gauge implementations do not support set via labels (stub); ignore
                pass
        except Exception:
            pass
        # For backward compatibility include counts as well
        counts_total = len(reqs)
        counts_present = counts_total - len(missing)
        return {
            'required_count': counts_total,
            'present_count': counts_present,
            'required_weight': total_weight,
            'present_weight': present_weight,
            'completeness': completeness,
            'missing': missing,
        }


# singleton
ENRICHMENT = EnrichmentService()
