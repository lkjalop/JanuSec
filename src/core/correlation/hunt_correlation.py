"""Correlation Engine (Phase 0 Skeleton)

Future: Combine multiple lane & base factors into synthesized higher-confidence correlation factors.
Current: No-op pass-through with metric stub.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Tuple

from .factor_constants import (
    CORR_ANOMALOUS_USER_AGENT_CHAIN,
    CORR_BEACON_RARE_JARM,
    CORR_BEACON_RARE_UA,
    # New extended correlation constants
    CORR_C2_MULTI_CHANNEL,
    CORR_DNS_FAST_FLUX_LIKE,
    # Newly expanded outputs
    CORR_DNS_TUNNEL_THROUGHPUT,
    CORR_EGRESS_EXFIL_PATTERN,
    CORR_ENCODED_PS_SIGNED_TO_UNSIGNED,
    CORR_EXFIL_VIA_DNS,
    CORR_HTTP_SUSPICIOUS_UPLOAD,
    CORR_KNOWN_BAD_SSL_ENCODED_PS,
    CORR_KNOWN_BAD_SSL_NEW_DOMAIN,
    CORR_LATERAL_PIVOT_POSSIBLE,
    CORR_MULTISURFACE_ANOMALY,
    CORR_OFFICE_PS_RARE_JA3,
    CORR_PERSISTENT_BEACON_CLUSTER,
    CORR_PHISH_MACRO_OUTBOUND_C2,
    CORR_PORT_SWEEP_PROBABLE,
    CORR_RANSOMWARE_BEACON_CHAIN,
    CORR_SSH_BRUTE_HIGH_FAIL,
    CORR_SSH_BRUTEFORCE_SUSPECTED,
    CORR_STEALTH_LATERAL_STAGING,
    CORR_TUNNEL_EXFIL_COMBO,
    # Newly added factors (this sprint)
    CORR_HEADER_INJECTION_BEACON,
    CORR_JA3_RARE_NEW_DOMAIN,
    CORR_BEACON_DNS_LONG_LABEL,
    CORR_UA_RARE_NEW_DOMAIN,
    CORR_PORT_SCATTER_JARM_RARE,
    CORR_CONN_ANOM_JA3_RARE,
    CORR_SSH_RARE_UA,
    JA3_RARE,
    OFFICE_MACRO_SPAWN_POWERSHELL,
    POWERSHELL_ENCODED_COMMAND,
    PROC_PARENT_CHAIN,
    SIGNED_TO_UNSIGNED_TRANSITION,
)
from .redis_cache import build_cache
from src.core.threat_modeling.ingestion_normalizer import normalize_factors
from src.core.correlation.multi_domain_chains import (
    DomainEvent,
    MultiDomainCorrelator,
    SecurityDomain,
    set_global_correlator,
)
from src.core.correlation.tier1_summarizer import summarize_tier1
from src.core.correlation.simple_metrics import inc_rule_fired, observe_rule_score
try:  # factor synthesis integration
    from src.core.correlation.factor_synthesis import Factor, FactorCategory
    from src.core.correlation.factor_synthesis_runtime import (
        get_factor_synthesis_engine,
        factor_category_for_name,
    )
except Exception:  # pragma: no cover
    Factor = None  # type: ignore
    FactorCategory = None  # type: ignore
    get_factor_synthesis_engine = None  # type: ignore
    factor_category_for_name = None  # type: ignore

try:
    from src.api import metrics_init as _metrics_init  # type: ignore
except Exception:  # pragma: no cover
    _metrics_init = None  # type: ignore

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self._init_metrics()
        # Temporal cache: maintain recent factor occurrences keyed by host (if available)
        # host key preference order: host, src_ip, source_ip.
        self.window_seconds = int(getattr(config, 'correlation_window_seconds', 300) or 300)
        self.max_events_per_host = 500  # cap memory
        self.host_factor_times: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque())
        # Fast lookup per host -> factor -> last timestamp (in-memory fallback)
        self.host_last_factor: dict[str, dict[str, float]] = defaultdict(dict)

        # Some legacy tests synchronously call asyncio.get_event_loop().run_until_complete(...)
        # After certain test modules, the default loop may be closed on Windows causing
        # RuntimeError("There is no current event loop"). Proactively ensure a loop is
        # set if none is running to stabilize those tests without modifying them.
        try:  # pragma: no cover - environment specific
            import asyncio as _asyncio
            try:
                _asyncio.get_running_loop()
            except RuntimeError:
                # No running loop; ensure a global default is available
                loop = _asyncio.new_event_loop()
                _asyncio.set_event_loop(loop)
        except Exception:
            pass

        self.redis_url = os.getenv('REDIS_URL') or getattr(config, 'REDIS_URL', None) or (config.get('REDIS_URL') if isinstance(config, dict) else None)
        # Use a dedicated temporal cache implementation (Redis-backed when configured)
        try:
            self.temporal_cache = build_cache(self.redis_url)
        except Exception:
            self.temporal_cache = build_cache(None)
        try:
            hopgraph = self._maybe_get_hopgraph()
        except Exception:
            hopgraph = None
        ttl = int(os.getenv('MULTI_DOMAIN_CHAIN_TTL','900') or 900)
        self.multi_domain_correlator = set_global_correlator(
            MultiDomainCorrelator(
                hopgraph_client=hopgraph,
                ttl_seconds=ttl,
            )
        )

    def _init_metrics(self):
        if getattr(self.__class__, '_init', False):
            return
        try:
            register_metrics()  # ensure class-level metrics exist
            self.__class__._init = True
        except Exception:
            pass

    def _get_host_key(self, event: dict | None) -> str | None:
        if not event:
            return None
        for k in ('host','src_ip','source_ip','hostname'):
            v = event.get(k)
            if v:
                return str(v)
        return None

    def _get_tenant_id(self, event: dict | None) -> str | None:
        if not event:
            return None
        # Common tenant header keys used across the platform
        for k in ('tenant_id', 'tenant', 'x_tenant_id', 'tenantId'):
            v = event.get(k)
            if v:
                return str(v)
        return None

    def _record_host_factors(self, host: str, factors: list[str]):
        now = time.time()
        dq = self.host_factor_times[host]
        for f in factors:
            dq.append((now, f))
            self.host_last_factor[host][f] = now
        # Persist into configured temporal cache (may be in-memory or redis)
        try:
            # Pass tenant_id if present to enable per-tenant isolation in RedisTemporalCache
            tenant_id = None
            try:
                # If called from correlate(), event context may be attached to self.last_event
                tenant_id = getattr(self, '_last_event_tenant', None)
            except Exception:
                tenant_id = None
            self.temporal_cache.record(host, list(factors), self.window_seconds, tenant_id=tenant_id)
        except Exception:
            pass
        # Trim old
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            old_t, old_f = dq.popleft()
            # Only delete last_factor if it matches timestamp (approx) not required for correctness
        # Cap length
        while len(dq) > self.max_events_per_host:
            dq.popleft()

    def _seen_within(self, host: str, factor: str, seconds: float) -> bool:
        try:
            if self.temporal_cache:
                tenant_id = getattr(self, '_last_event_tenant', None)
                if self.temporal_cache.seen_within(host, factor, seconds, tenant_id=tenant_id):
                    return True
        except Exception:
            pass
        ts = self.host_last_factor.get(host, {}).get(factor)
        if not ts:
            return False
        return (time.time() - ts) <= seconds

    def _maybe_get_hopgraph(self):
        try:
            from src.core.graph.api_hopgraph import get_graph  # type: ignore
            return get_graph()
        except Exception:
            return None

    def _infer_domain(self, factors: Iterable[str]) -> SecurityDomain:
        order = [
            ('email:', SecurityDomain.EMAIL),
            ('identity:', SecurityDomain.IDENTITY),
            ('iam:', SecurityDomain.IDENTITY),
            ('vpn:', SecurityDomain.REMOTE_ACCESS),
            ('rdp:', SecurityDomain.REMOTE_ACCESS),
            ('endpoint:', SecurityDomain.ENDPOINT),
            ('process:', SecurityDomain.ENDPOINT),
            ('net:', SecurityDomain.NETWORK),
            ('dns:', SecurityDomain.NETWORK),
            ('cloud:', SecurityDomain.CLOUD),
            ('data:', SecurityDomain.DATA),
            ('api:', SecurityDomain.API),
        ]
        fset = [str(f).lower() for f in factors]
        for prefix, domain in order:
            if any(f.startswith(prefix) for f in fset):
                return domain
        return SecurityDomain.ENDPOINT

    def _build_synthesis_context(self, event: dict | None) -> Dict[str, Any]:
        if not isinstance(event, dict):
            return {}
        ctx: Dict[str, Any] = {}
        role = str(event.get('role') or event.get('user_role') or '').strip().lower()
        if role:
            ctx['user_role'] = role
        severity = str(event.get('severity') or '').strip().lower()
        if severity:
            ctx['severity'] = severity
        source = str(event.get('source') or event.get('ingest_source') or '').strip().lower()
        if source:
            ctx['source'] = source
        tenant = str(event.get('tenant_id') or '').strip().lower()
        if tenant:
            ctx['tenant'] = tenant
        return ctx

    def _append_factor_synthesis_insight(self, event: dict | None, factor_names: Iterable[str]) -> None:
        if not event or not factor_names:
            return
        if not (get_factor_synthesis_engine and Factor and FactorCategory and factor_category_for_name):
            return
        engine = get_factor_synthesis_engine()
        if engine is None:
            return
        factors: List[Factor] = []
        now_dt = datetime.utcnow()
        for name in factor_names:
            try:
                category = factor_category_for_name(name)
            except Exception:
                category = FactorCategory.META
            try:
                factors.append(
                    Factor(
                        name=name,
                        category=category,
                        timestamp=now_dt,
                        base_weight=0.5,
                        metadata={},
                    )
                )
            except Exception:
                continue
        if not factors:
            return
        try:
            result = engine.synthesize(factors, context=self._build_synthesis_context(event))
        except Exception:
            return
        insight = {
            'type': 'factor_synthesis',
            'confidence': result.confidence,
            'final_score': result.final_score,
            'synergies': result.synergies_detected,
            'ttl_seconds': 0,
            'factor_synthesis': {
                'final_score': result.final_score,
                'confidence': result.confidence,
                'contributing_factors': result.contributing_factors,
                'synergies': result.synergies_detected,
                'context_multiplier': result.context_multiplier,
                'decay_applied': result.decay_applied,
                'explanation': result.explanation,
            },
        }
        event.setdefault('correlation_insights', []).append(insight)

    def _run_multi_domain_chain(self, event: dict | None, factors: List[str], new: List[str]) -> None:
        if not self.multi_domain_correlator or not event:
            return
        entities = {
            'user': str(event.get('user') or event.get('principal') or ''),
            'host': str(event.get('host') or event.get('hostname') or event.get('device') or ''),
            'ip': str(event.get('src_ip') or event.get('source_ip') or event.get('ip') or event.get('dst_ip') or ''),
        }
        if not entities['user'] and not entities['host']:
            return
        domain = self._infer_domain(factors)
        ts = float(event.get('ts') or time.time())
        try:
            metadata = {}
            if isinstance(event.get('mitre'), list):
                metadata['mitre'] = event['mitre']
        except Exception:
            metadata = {}
        domain_event = DomainEvent(
            domain=domain,
            event_id=str(event.get('event_id') or event.get('id') or f"evt-{int(ts)}"),
            timestamp=ts,
            factors=list(factors),
            entities=entities,
            score=float(event.get('score') or event.get('risk_score') or 0.0),
            metadata=metadata,
        )
        chain = self.multi_domain_correlator.process_event(domain_event)
        if chain:
            new.append(f"corr_multi_domain_chain:{len(chain.domains_involved)}")
            insights = event.setdefault('correlation_insights', [])
            insight_payload = {
                'type': 'multi_domain_chain',
                'chain_id': chain.chain_id,
                'domains': [d.value for d in chain.domains_involved],
                'confidence': chain.confidence,
                'narrative': chain.narrative,
                'recommendations': chain.recommendations,
                'recommendation_catalog': chain.recommendation_catalog,
                'entity_resolution': chain.entity_resolution,
                'hopgraph_snapshot': chain.hopgraph_snapshot,
                'hopgraph_context': chain.hopgraph_context,
                'generated_at': chain.generated_at,
                'expires_at': chain.expires_at,
                'ttl_seconds': chain.ttl_seconds,
                'raw_total_score': chain.raw_total_score,
                'factor_synthesis': chain.synthesis,
            }
            insights.append(insight_payload)
            try:
                # Push into incident aggregator for later incident rendering
                from src.incidents.aggregator import GLOBAL_INCIDENTS  # type: ignore
            except Exception:
                GLOBAL_INCIDENTS = None  # type: ignore
            if GLOBAL_INCIDENTS:
                try:
                    GLOBAL_INCIDENTS.ingest(event, list(factors))
                except Exception:
                    pass

    async def correlate(self, factors: list[str], *, tp_factors: list[str] | None = None, fp_factors: list[str] | None = None, event: dict | None = None) -> list[str]:
        # Latency instrumentation (idempotent)
        _lat_hist = None
        start_t = time.time()
        try:
            if metric_histogram := getattr(__import__('core.metrics.registry', fromlist=['metric_histogram']), 'metric_histogram', None):  # type: ignore
                _lat_hist = metric_histogram('hunt_correlation', 'latency', 'Correlation engine latency', labels=['had_event'])
        except Exception:
            _lat_hist = None
        new: list[str] = []
        # Normalize any legacy aliases at the ingestion boundary so downstream
        # rules only need to reason about canonical factor names.
        fset = set(normalize_factors(factors))
        host = self._get_host_key(event)
        # store tenant context for internal helpers
        self._last_event_tenant = self._get_tenant_id(event)
        if host:
            # Record current baseline factors into temporal cache for future events
            self._record_host_factors(host, list(fset))
        # Record before stats (if provided)
        if tp_factors and getattr(self.__class__, 'corr_tp_before', None):
            try:
                for _ in tp_factors: self.__class__.corr_tp_before.inc()
            except Exception: pass
        if fp_factors and getattr(self.__class__, 'corr_fp_before', None):
            try:
                for _ in fp_factors: self.__class__.corr_fp_before.inc()
            except Exception: pass
        # Rule 1: Office macro spawning PS + rare JA3
        if OFFICE_MACRO_SPAWN_POWERSHELL in fset and JA3_RARE in fset:
            new.append(CORR_OFFICE_PS_RARE_JA3)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='office_ps_rare_ja3').inc()
                except Exception: pass
        # Rule 2: Encoded PS + signed→unsigned transition synergy
        if POWERSHELL_ENCODED_COMMAND in fset and SIGNED_TO_UNSIGNED_TRANSITION in fset:
            new.append(CORR_ENCODED_PS_SIGNED_TO_UNSIGNED)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='encoded_signed_unsigned').inc()
                except Exception: pass
        # Rule 3: Lateral pivot possible (generic lineage chain + rare JA3)
        if PROC_PARENT_CHAIN in fset and JA3_RARE in fset:
            new.append(CORR_LATERAL_PIVOT_POSSIBLE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='lateral_pivot_possible').inc()
                except Exception: pass
        # --- Extended correlation rule set (temporal + multi-signal) ---
        # Helper lambdas for temporal window checks
        def recently(f: str, window: int = 300) -> bool:
            if not host:
                return False
            return self._seen_within(host, f, window)

        # 4: C2 multi-channel: dns:tunnel_suspected + net:beacon_periodic (same event or temporal window)
        if ('dns:tunnel_suspected' in fset and 'net:beacon_periodic' in fset) or (
            'dns:tunnel_suspected' in fset and recently('net:beacon_periodic')) or (
            'net:beacon_periodic' in fset and recently('dns:tunnel_suspected')):
            new.append(CORR_C2_MULTI_CHANNEL)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='c2_multichannel').inc()
                except Exception: pass

        # 5: Known bad SSL + encoded PS
        if 'ssl:ja3_known_bad' in fset and POWERSHELL_ENCODED_COMMAND in fset:
            new.append(CORR_KNOWN_BAD_SSL_ENCODED_PS)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='known_bad_ssl_encoded_ps').inc()
                except Exception: pass

        # 6: Egress exfil pattern: port scatter + connection rate anomaly
        if 'net:egress_port_scatter' in fset and 'conn_rate_anomaly' in fset:
            new.append(CORR_EGRESS_EXFIL_PATTERN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='egress_exfil_pattern').inc()
                except Exception: pass

        # 7: Multisurface anomaly: ja3 rare + long DNS label + rare UA (all in recent window)
        if (
            ('ssl:ja3_rare' in fset or recently('ssl:ja3_rare')) and
            ('dns:long_label' in fset or recently('dns:long_label')) and
            ('http:user_agent_rare' in fset or recently('http:user_agent_rare'))
        ):
            new.append(CORR_MULTISURFACE_ANOMALY)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='multisurface_anomaly').inc()
                except Exception: pass

        # 8: Known bad SSL + brand new domain
        if 'ssl:ja3_known_bad' in fset and ('domain_novel_observed' in fset or recently('domain_novel_observed')):
            new.append(CORR_KNOWN_BAD_SSL_NEW_DOMAIN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='known_bad_ssl_new_domain').inc()
                except Exception: pass

        # 9: Beacon pattern + rare UA (same or temporal)
        if ('net:beacon_periodic' in fset and 'http:user_agent_rare' in fset) or (
            'net:beacon_periodic' in fset and recently('http:user_agent_rare')) or (
            'http:user_agent_rare' in fset and recently('net:beacon_periodic')):
            new.append(CORR_BEACON_RARE_UA)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='beacon_rare_ua').inc()
                except Exception: pass

        # 10: Tunnel exfil combo: dns tunneling suspected + egress port scatter
        if 'dns:tunnel_suspected' in fset and 'net:egress_port_scatter' in fset:
            new.append(CORR_TUNNEL_EXFIL_COMBO)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='tunnel_exfil_combo').inc()
                except Exception: pass

        

        # 12: Beacon + rare JARM combination
        if 'net:beacon_periodic' in fset and ('ssl:jarm_rare' in fset or recently('ssl:jarm_rare')):
            new.append(CORR_BEACON_RARE_JARM)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='beacon_rare_jarm').inc()
                except Exception: pass

        # 13: Phishing macro followed by outbound C2 (office macro -> powershell + new domain)
        if OFFICE_MACRO_SPAWN_POWERSHELL in fset and ('domain_novel_observed' in fset or recently('domain_novel_observed')):
            new.append(CORR_PHISH_MACRO_OUTBOUND_C2)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='phish_macro_outbound_c2').inc()
                except Exception: pass

        # 14: DNS tunnel throughput combined with port scatter -> tunnel throughput correlation
        if ('dns:tunnel_suspected' in fset or recently('dns:tunnel_suspected')) and ('net:egress_port_scatter' in fset or recently('net:egress_port_scatter')):
            new.append(CORR_DNS_TUNNEL_THROUGHPUT)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='dns_tunnel_throughput').inc()
                except Exception: pass

        # 15: Port sweep probable when many distinct ports seen and conn_rate high
        if ('net:egress_port_scatter' in fset) and ('conn_rate_anomaly' in fset or recently('conn_rate_anomaly')):
            new.append(CORR_PORT_SWEEP_PROBABLE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='port_sweep_probable').inc()
                except Exception: pass

        # 16: Ransomware-like beacon chain: persistent beacon cluster + domain novelty
        if ('net:beacon_periodic' in fset or recently('net:beacon_periodic')) and ('domain_novel_observed' in fset or recently('domain_novel_observed')):
            new.append(CORR_RANSOMWARE_BEACON_CHAIN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='ransomware_beacon_chain').inc()
                except Exception: pass

        # 17: Exfil via DNS indicator
        if ('dns:tunnel_suspected' in fset) and ('http:user_agent_rare' in fset or recently('http:user_agent_rare')):
            new.append(CORR_EXFIL_VIA_DNS)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='exfil_via_dns').inc()
                except Exception: pass

        # 18: Stealth lateral staging: process lineage + rare ja3 or ssh_fp novelty
        if (OFFICE_MACRO_SPAWN_POWERSHELL in fset or PROC_PARENT_CHAIN in fset) and (JA3_RARE in fset or 'ssh_fp_novel' in fset or recently('ssh_fp_novel')):
            new.append(CORR_STEALTH_LATERAL_STAGING)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='stealth_lateral_staging').inc()
                except Exception: pass

        # 19: Anomalous UA chain
        if ('http:user_agent_rare' in fset) and ('ssl:ja3_rare' in fset or recently('ssl:ja3_rare')):
            new.append(CORR_ANOMALOUS_USER_AGENT_CHAIN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='anomalous_user_agent_chain').inc()
                except Exception: pass

        # 20: DNS fast-flux like: many novel domains from same host
        if ('domain_novel_observed' in fset or recently('domain_novel_observed')) and ('dns:long_label' in fset or recently('dns:long_label')):
            new.append(CORR_DNS_FAST_FLUX_LIKE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='dns_fast_flux_like').inc()
                except Exception: pass

        # 21: SSH brute high fail
        if ('ssh_fp_rare' in fset or recently('ssh_fp_rare')) and ('conn_rate_anomaly' in fset or recently('conn_rate_anomaly')):
            new.append(CORR_SSH_BRUTE_HIGH_FAIL)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='ssh_brute_high_fail').inc()
                except Exception: pass

        # 22: Persistent beacon cluster across hosts
        if ('net:beacon_periodic' in fset or recently('net:beacon_periodic')) and ('net:egress_port_scatter' in fset or recently('net:egress_port_scatter')):
            new.append(CORR_PERSISTENT_BEACON_CLUSTER)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='persistent_beacon_cluster').inc()
                except Exception: pass

        # 23: Header injection pattern combined with beacon-like traffic
        if ('http:header_injection_pattern' in fset or recently('http:header_injection_pattern')) and ('net:beacon_periodic' in fset or recently('net:beacon_periodic')):
            new.append(CORR_HEADER_INJECTION_BEACON)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='header_injection_beacon').inc()
                except Exception: pass

        # 24: Rare JA3 followed by new domain access
        if ('ssl:ja3_rare' in fset or recently('ssl:ja3_rare')) and ('domain_novel_observed' in fset or recently('domain_novel_observed')):
            new.append(CORR_JA3_RARE_NEW_DOMAIN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='ja3_rare_new_domain').inc()
                except Exception: pass

        # 25: Beacon + DNS long label (possible exfil chunks)
        if ('net:beacon_periodic' in fset or recently('net:beacon_periodic')) and ('dns:long_label' in fset or recently('dns:long_label')):
            new.append(CORR_BEACON_DNS_LONG_LABEL)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='beacon_dns_long_label').inc()
                except Exception: pass

        # 26: Rare UA then new domain
        if ('http:user_agent_rare' in fset or recently('http:user_agent_rare')) and ('domain_novel_observed' in fset or recently('domain_novel_observed')):
            new.append(CORR_UA_RARE_NEW_DOMAIN)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='ua_rare_new_domain').inc()
                except Exception: pass

        # Vuln-aware correlations (CVSS>=9 context)
        # A: High CVSS asset with egress spike
        if ('vuln:cvss_ge_9' in fset) and (('egress_volume_spike' in fset) or recently('egress_volume_spike') or ('an:egress_residual_spike' in fset) or recently('an:egress_residual_spike')):
            new.append('corr:vuln_host_egress_spike')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='vuln_host_egress_spike').inc()
                except Exception: pass
        # B: High CVSS asset with beacon-like
        if ('vuln:cvss_ge_9' in fset) and (('net:beacon_periodic' in fset) or recently('net:beacon_periodic')):
            new.append('corr:vuln_host_beacon')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='vuln_host_beacon').inc()
                except Exception: pass
        # C: High CVSS asset with LOLBin TF-IDF rare commandline
        if ('vuln:cvss_ge_9' in fset) and any(str(f).startswith('endpoint:lolbin_cmd_tfidf_') for f in fset):
            new.append('corr:lolbin_on_vuln_asset')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='lolbin_on_vuln_asset').inc()
                except Exception: pass

        # 27: Port scatter with rare JARM
        if ('net:egress_port_scatter' in fset or recently('net:egress_port_scatter')) and ('ssl:jarm_rare' in fset or recently('ssl:jarm_rare')):
            new.append(CORR_PORT_SCATTER_JARM_RARE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='port_scatter_jarm_rare').inc()
                except Exception: pass

        # 28: Connection anomaly with rare JA3
        if ('conn_rate_anomaly' in fset or recently('conn_rate_anomaly')) and ('ssl:ja3_rare' in fset or recently('ssl:ja3_rare')):
            new.append(CORR_CONN_ANOM_JA3_RARE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='conn_anom_ja3_rare').inc()
                except Exception: pass

        # 29: SSH rare + UA rare (suspicious tooling)
        if ('ssh_fp_rare' in fset or recently('ssh_fp_rare')) and ('http:user_agent_rare' in fset or recently('http:user_agent_rare')):
            new.append(CORR_SSH_RARE_UA)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='ssh_rare_ua').inc()
                except Exception: pass

        # Starter: egress residual spike combined with rare/new domain
        if ('an:egress_residual_spike' in fset or recently('an:egress_residual_spike')) and (('rare:domain_tenant' in fset) or ('new_domain_seen' in fset) or recently('rare:domain_tenant')):
            new.append('corr:egress_residual_rare_domain')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='egress_residual_rare_domain').inc()
                except Exception: pass

        # Starter: auth burst with lateral motif
        if ('chg:auth_burst' in fset or recently('chg:auth_burst')) and (('lateral_movement_candidate' in fset) or ('graph:motif_auth_net' in fset) or recently('graph:motif_auth_net')):
            new.append('corr:auth_burst_lateral_motif')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='auth_burst_lateral_motif').inc()
                except Exception: pass

        # Starter: high lateral velocity and DC triad motif
        if ('graph:lateral_velocity_hph' in fset or recently('graph:lateral_velocity_hph')) and ('graph:triad_dc' in fset or recently('graph:triad_dc')):
            new.append('corr:lateral_velocity_triad_dc')
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='lateral_velocity_triad_dc').inc()
                except Exception: pass

        try:
            self._run_multi_domain_chain(event, list(fset), new)
        except Exception:
            pass

        # update host cache gauge if available (do on every call for accuracy)
        try:
            if getattr(self.__class__, 'corr_host_cache_gauge', None):
                self.__class__.corr_host_cache_gauge.set(len(self.host_factor_times))
        except Exception:
            pass

        if event:
            try:
                self._append_factor_synthesis_insight(event, sorted(fset))
            except Exception:
                pass

        if new:
            if getattr(self.__class__, 'corr_factors_total', None):
                for _ in new:
                    try:
                        self.__class__.corr_factors_total.inc()
                    except Exception:
                        pass
            # update host cache gauge if available
            try:
                if getattr(self.__class__, 'corr_host_cache_gauge', None):
                    self.__class__.corr_host_cache_gauge.set(len(self.host_factor_times))
            except Exception:
                pass
            # Post-correlation stats (simplistic: treat new factors as TP contributors if any original TP)
            if tp_factors and getattr(self.__class__, 'corr_tp_after', None):
                try:
                    for _ in tp_factors: self.__class__.corr_tp_after.inc()
                except Exception: pass
            if fp_factors and getattr(self.__class__, 'corr_fp_after', None):
                try:
                    for _ in fp_factors: self.__class__.corr_fp_after.inc()
                except Exception: pass
        # If the event carried a correlation_emission (from rule modules), persist a Tier-1 summary and emit metrics
        try:
            if event and isinstance(event, dict):
                emission = event.get('correlation_emission')
                if emission:
                    try:
                        # persist deterministic Tier-1 summary for UI + LLM consumers
                        event['tier1_summary'] = summarize_tier1(event)
                    except Exception:
                        pass
                    # metrics: increment counters and observe score
                    try:
                        rule = emission.get('rule') or 'unknown'
                        score = float(emission.get('computed_score') or 0.0)
                        try:
                            inc_rule_fired(rule)
                            observe_rule_score(rule, score)
                        except Exception:
                            pass
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            return new
        finally:
            try:
                if _lat_hist:
                    _lat_hist.labels(had_event='1' if event else '0').observe(max(0.0, time.time() - start_t))
            except Exception:
                pass

    # Fallback: ensure gauge is updated even when no new factors generated

# Factory
_engine_instance: CorrelationEngine | None = None

def register_metrics(registry: Any | None = None) -> None:
    """Idempotently register correlation engine metrics into shared registry.

    Uses safe helper wrappers so duplicate registration does not raise and tests
    can invoke multiple times without side-effects.
    """
    try:
        if _metrics_init is None:
            return
        _metrics_init.ensure_metrics()
        sc = getattr(_metrics_init, '_safe_counter', None)
        sg = getattr(_metrics_init, '_safe_gauge', None)
        if not sc or not sg:
            return
        cls = CorrelationEngine
        # Only assign if not already present to preserve counters across calls
        if not hasattr(cls, 'corr_factors_total'):
            cls.corr_factors_total = sc('hunt_correlation_factors_total','Correlation synthesized factors emitted')
        if not hasattr(cls, 'corr_rule_hits'):
            cls.corr_rule_hits = sc('hunt_correlation_rule_hits_total','Correlation rule hit count', ['rule'])
        if not hasattr(cls, 'corr_tp_before'):
            cls.corr_tp_before = sc('hunt_corr_tp_before_total','Correlation pipeline true-positive factors before correlation')
        if not hasattr(cls, 'corr_tp_after'):
            cls.corr_tp_after = sc('hunt_corr_tp_after_total','Correlation pipeline true-positive factors after correlation')
        if not hasattr(cls, 'corr_fp_before'):
            cls.corr_fp_before = sc('hunt_corr_fp_before_total','Correlation pipeline false-positive factors before correlation')
        if not hasattr(cls, 'corr_fp_after'):
            cls.corr_fp_after = sc('hunt_corr_fp_after_total','Correlation pipeline false-positive factors after correlation')
        if not hasattr(cls, 'corr_host_cache_gauge'):
            cls.corr_host_cache_gauge = sg('hunt_correlation_host_cache_size','Number of hosts currently tracked by temporal correlation cache')
    except Exception:
        pass

def get_correlation_engine(config, *, force_new: bool = False) -> CorrelationEngine:
    """Return a singleton CorrelationEngine by default.

    If `force_new=True` a fresh instance is returned (tests / CI should use this
    for isolation).
    """
    global _engine_instance
    if force_new:
        return CorrelationEngine(config)
    if _engine_instance is None:
        _engine_instance = CorrelationEngine(config)
    return _engine_instance


def create_correlation_engine(config) -> CorrelationEngine:
    """Backward-compatible constructor for tests — returns fresh instance."""
    return CorrelationEngine(config)
