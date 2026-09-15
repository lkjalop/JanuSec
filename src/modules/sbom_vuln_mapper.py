"""SBOM Vulnerability Mapper Module

Generates sbom:* factors from vulnerability aggregates with bounded confidence influence.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None    # type: ignore

class SBOMVulnMapper:
    def __init__(self, config):
        self.config = config
        self.cap = float(getattr(config, 'get', lambda *a, **k: {})('sbom',{}).get('confidence_cap',0.20)) if hasattr(config,'get') else 0.20
        if not hasattr(SBOMVulnMapper,'_metrics_init'):
            try:
                if Counter:
                    SBOMVulnMapper.factor_counter = Counter('sbom_vuln_factors_total','Count of sbom vulnerability factors emitted',['factor'])  # type: ignore
                if Gauge:
                    SBOMVulnMapper.density_gauge = Gauge('sbom_density_ratio','SBOM high+critical density ratio',['component_key'])  # type: ignore
                SBOMVulnMapper._metrics_init = True
            except Exception:
                pass

    async def initialize(self):
        return

    async def health_check(self):
        return True

    async def shutdown(self):
        return

    def map_event(self, tenant: str, component_key: str, existing_factors: list[str]) -> dict[str, Any]:
        from repositories.sbom_vuln_agg_repo import get_aggregate
        agg = get_aggregate(tenant, component_key)
        if not agg:
            return {'factors': [], 'delta': 0.0, 'meta': None}
        sc = agg.severity_counts
        crit = sc.get('critical',0)
        high = sc.get('high',0)
        med = sc.get('medium',0)
        low = sc.get('low',0)
        cvss_max = float(getattr(agg, 'cvss_max', 0.0) or 0.0)
        factors: list[str] = []
        pos_deltas: dict[str,float] = {}
        # Factor rules
        if crit > 0:
            factors.append('sbom:cve_critical'); pos_deltas['sbom:cve_critical']=0.08
        if (high + crit) >= 3:
            factors.append('sbom:cve_high_density'); pos_deltas['sbom:cve_high_density']=0.05
        if (med + high + crit) >= 25:
            factors.append('sbom:cve_backlog_large'); pos_deltas['sbom:cve_backlog_large']=0.03
        # Age stale (180d)
        age_days = (time.time() - agg.oldest_vuln_ts) / 86400.0
        if age_days >= 180:
            factors.append('sbom:vuln_age_stale'); pos_deltas['sbom:vuln_age_stale']=0.02
        # Supply chain drift (if existing factor present)
        if 'component_hash_drift' in existing_factors:
            factors.append('sbom:supply_chain_drift'); pos_deltas['sbom:supply_chain_drift']=0.04
        # High CVSS presence (from max observed)
        try:
            if cvss_max >= 9.0:
                if 'vuln:cvss_ge_9' not in factors:
                    factors.append('vuln:cvss_ge_9')
                # Small additive signal; respects overall cap below
                pos_deltas['vuln:cvss_ge_9'] = max(pos_deltas.get('vuln:cvss_ge_9', 0.0), 0.03)
        except Exception:
            pass
        # Emit a non-scoring factor carrying cvss_max for SSE timelines/visibility
        try:
            if cvss_max and cvss_max > 0:
                factors.append(f'vuln:cvss_max:{cvss_max:.1f}')
        except Exception:
            pass
        # Cap scaling
        total = sum(pos_deltas.values())
        if total > self.cap and total > 0:
            scale = self.cap / total
        else:
            scale = 1.0
        delta_total = 0.0
        scaled = {}
        for f, d in pos_deltas.items():
            adj = d * scale
            scaled[f] = adj
            delta_total += adj
            # metrics
            try:
                if hasattr(self.__class__,'factor_counter'):
                    try:
                        from src.api.metrics_tenant_helper import emit_labels_with_guard
                        from src.api.server import get_server_runtime_state as _get_rt
                        labels = emit_labels_with_guard(_get_rt(None), {'factor': f}, None)
                        self.__class__.factor_counter.labels(**labels).inc()
                    except Exception:
                        try: self.__class__.factor_counter.labels(factor=f).inc()  # type: ignore
                        except Exception: pass
            except Exception: pass
        # density gauge
        high_density_ratio = (high + crit) / max(1, (crit+high+med+low))
        try:
            if hasattr(self.__class__,'density_gauge'):
                try:
                    from src.api.metrics_tenant_helper import emit_labels_with_guard
                    from src.api.server import get_server_runtime_state as _get_rt
                    labels = emit_labels_with_guard(_get_rt(None), {'component_key': component_key}, None)
                    self.__class__.density_gauge.labels(**labels).set(high_density_ratio)
                except Exception:
                    try: self.__class__.density_gauge.labels(component_key=component_key).set(high_density_ratio)  # type: ignore
                    except Exception: pass
        except Exception: pass
        return {
            'factors': factors,
            'delta': round(delta_total,4),
            'meta': {
                'severity_counts': sc,
                'age_days': round(age_days,1),
                'scaled_deltas': scaled,
                'density_ratio': round(high_density_ratio,4),
                'cvss_max': cvss_max,
            }
        }
