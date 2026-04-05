"""Multi-domain correlator that stitches events across domains with TTL & narratives."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import os
import time
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from src.core.correlation.factor_synthesis import Factor, FactorCategory
from src.core.correlation.factor_synthesis_runtime import (
    factor_category_for_name,
    get_factor_synthesis_engine,
)
from src.core.entity_resolution import resolve_entity_key


class SecurityDomain(Enum):
    ENDPOINT = "endpoint"
    NETWORK = "network"
    EMAIL = "email"
    IDENTITY = "identity"
    CLOUD = "cloud"
    DATA = "data"
    REMOTE_ACCESS = "remote"
    API = "api"


@dataclass
class DomainEvent:
    domain: SecurityDomain
    event_id: str
    timestamp: float
    factors: List[str]
    entities: Dict[str, str] = field(default_factory=dict)
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MultiDomainChain:
    chain_id: str
    domains_involved: List[SecurityDomain]
    events: List[DomainEvent]
    total_score: float
    confidence: float
    mitre_chain: List[str]
    narrative: str
    recommendations: List[str]
    hopgraph_snapshot: Optional[Dict[str, Any]] = None
    entity_resolution: Optional[Dict[str, Any]] = None
    recommendation_catalog: List[Dict[str, Any]] = field(default_factory=list)
    hopgraph_context: Optional[Dict[str, Any]] = None
    generated_at: float = field(default_factory=lambda: time.time())
    expires_at: float = 0.0
    ttl_seconds: int = 0
    raw_total_score: float = 0.0
    synthesis: Optional[Dict[str, Any]] = None
    memory_jobs: List[Dict[str, Any]] = field(default_factory=list)


class MultiDomainCorrelator:
    """Tracks events per entity and emits chains when multiple domains overlap."""

    def __init__(
        self,
        hopgraph_client: Optional[Any] = None,
        ttl_seconds: int = 900,
        recommendation_overrides: Optional[Dict[str, List[str]]] = None,
    ):
        self._events: Dict[str, List[DomainEvent]] = {}
        self._event_index: Dict[str, DomainEvent] = {}
        self._hopgraph = hopgraph_client
        self._ttl = max(60, ttl_seconds)
        self._hash_len = int(os.getenv('MULTI_DOMAIN_CHAIN_HASH_LEN', '12') or 12)
        self._clean_interval = max(0, int(os.getenv('MULTI_DOMAIN_CHAIN_CLEAN_INTERVAL_SECONDS', '0') or 0))
        self._last_cleanup = 0.0
        self._recommendation_overrides = recommendation_overrides or {}
        self._recent_chains: Deque[MultiDomainChain] = deque(
            maxlen=max(5, int(os.getenv('MULTI_DOMAIN_CHAIN_HISTORY_MAX', '25') or 25))
        )
        env_catalog = os.getenv('MULTI_DOMAIN_CHAIN_RECOMMENDATIONS_JSON')
        if env_catalog:
            try:
                parsed = json.loads(env_catalog)
                if isinstance(parsed, dict):
                    for domain, hints in parsed.items():
                        if isinstance(hints, list):
                            self._recommendation_overrides.setdefault(domain, [])
                            self._recommendation_overrides[domain].extend([str(h) for h in hints])
            except Exception:
                pass
        self._total_emitted = 0
        self._last_entity_preview: Dict[str, Any] | None = None

    def process_event(self, event: DomainEvent) -> Optional[MultiDomainChain]:
        entity_key, preview = self._entity_key(event.entities)
        pivot_tokens = self._pivot_tokens(event.entities, event.metadata, preview)
        if not entity_key and not pivot_tokens:
            return None

        now = event.timestamp or time.time()
        self._maybe_cleanup(now)
        self._event_index[event.event_id] = event
        for token in pivot_tokens:
            bucket = self._events.setdefault(token, [])
            bucket.append(event)
            self._prune(token, now)
        bucket = self._collect_related_events(pivot_tokens, now)

        domains = self._unique_domains(bucket)
        if len(domains) < 2:
            return None

        sorted_events = sorted(bucket, key=lambda e: e.timestamp)
        memory_jobs: List[Dict[str, Any]] = []
        seen_job_ids: set[str] = set()
        for ev in sorted_events:
            ev_mem = ev.metadata.get('memory_jobs') if ev.metadata else None
            if not isinstance(ev_mem, list):
                continue
            for job in ev_mem:
                if not isinstance(job, dict):
                    continue
                jid = job.get('job_id')
                if jid and jid in seen_job_ids:
                    continue
                seen_job_ids.add(jid)
                memory_jobs.append(job)

        shared_pivots = self._shared_pivots(sorted_events)
        chain_seed = entity_key or (pivot_tokens[0] if pivot_tokens else event.event_id)
        chain_id = f"chain-{chain_seed}-{int(now)}"
        raw_total_score = sum(max(0.1, e.score or 0.0) for e in sorted_events)
        synth_score, synth_confidence, synthesis_summary = self._synthesize_chain(sorted_events, domains)
        total_score = synth_score if synth_score is not None else raw_total_score
        confidence = (
            synth_confidence
            if synth_confidence is not None
            else min(0.99, 0.3 + len(domains) * 0.1 + total_score * 0.05)
        )
        hopgraph_context = self._hopgraph_context(preview, sorted_events, shared_pivots)
        narrative = self._build_narrative(entity_key, domains, sorted_events, hopgraph_context)
        recommendation_catalog = self._build_recommendation_catalog(domains)
        recommendations = [rec['action'] for rec in recommendation_catalog]
        mitre_chain = self._infer_mitre(sorted_events)
        hopgraph_snapshot = self._capture_hopgraph(entity_key)
        expires_at = now + self._ttl

        chain = MultiDomainChain(
            chain_id=chain_id,
            domains_involved=list(domains),
            events=list(sorted_events),
            total_score=round(total_score, 4),
            confidence=round(confidence, 4),
            mitre_chain=mitre_chain,
            narrative=narrative,
            recommendations=recommendations,
            hopgraph_snapshot=hopgraph_snapshot,
            entity_resolution=preview,
            recommendation_catalog=recommendation_catalog,
            hopgraph_context=hopgraph_context,
            generated_at=now,
            expires_at=expires_at,
            ttl_seconds=self._ttl,
            raw_total_score=round(raw_total_score, 4),
            synthesis=synthesis_summary,
            memory_jobs=memory_jobs,
        )
        self._recent_chains.append(chain)
        self._total_emitted += 1
        self._last_entity_preview = preview
        return chain

    # ------------------------------------------------------------------ helpers
    def _entity_key(self, entities: Dict[str, str]) -> Tuple[Optional[str], Dict[str, Any]]:
        preview = resolve_entity_key(entities, hash_len=self._hash_len)
        return preview.get('key'), preview

    def _pivot_tokens(
        self,
        entities: Dict[str, str],
        metadata: Dict[str, Any] | None,
        preview: Dict[str, Any] | None = None,
    ) -> List[str]:
        primary = (preview or {}).get('primary') or {}
        tokens: List[str] = []
        user = primary.get('user', {}).get('normalized')
        host = primary.get('host', {}).get('normalized')
        ip_src = primary.get('ip_src', {}).get('normalized')
        if user:
            tokens.append(f'user:{user}')
        if host:
            tokens.append(f'host:{host}')
        if ip_src:
            tokens.append(f'ip:{ip_src}')
        if isinstance(metadata, dict):
            resource = str(metadata.get('resource') or metadata.get('resource_id') or '').strip().lower()
            corr = str(metadata.get('correlation_id') or '').strip().lower()
            if resource:
                tokens.append(f'resource:{resource}')
            if corr:
                tokens.append(f'corr:{corr}')
        deduped: List[str] = []
        for token in tokens:
            if token not in deduped:
                deduped.append(token)
        return deduped

    def _prune(self, entity_key: str, now: float) -> List[DomainEvent]:
        window = now - self._ttl
        bucket = self._events.get(entity_key, [])
        if not bucket:
            return []
        self._events[entity_key] = [ev for ev in bucket if ev.timestamp >= window]
        if not self._events[entity_key]:
            self._events.pop(entity_key, None)
            return []
        return self._events[entity_key]

    def _collect_related_events(self, pivot_tokens: List[str], now: float) -> List[DomainEvent]:
        window = now - self._ttl
        related: Dict[str, DomainEvent] = {}
        for token in pivot_tokens:
            for ev in self._events.get(token, []):
                if ev.timestamp < window:
                    continue
                related[ev.event_id] = ev
        return list(related.values())

    def _maybe_cleanup(self, now: float) -> None:
        if not self._clean_interval:
            return
        if (now - self._last_cleanup) < self._clean_interval:
            return
        self.cleanup()
        self._last_cleanup = now

    def _unique_domains(self, events: Iterable[DomainEvent]) -> List[SecurityDomain]:
        seen: List[SecurityDomain] = []
        for ev in events:
            if ev.domain not in seen:
                seen.append(ev.domain)
        return seen

    def _build_narrative(
        self,
        entity_key: str,
        domains: Iterable[SecurityDomain],
        events: Iterable[DomainEvent],
        hopgraph_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        label = entity_key or 'shared pivot'
        parts = [f"Entity {label} touched domains {', '.join(d.value for d in domains)}."]
        for ev in events:
            parts.append(f"{time.strftime('%H:%M:%S', time.gmtime(ev.timestamp))} -> {ev.domain.value} ({ev.event_id})")
        if hopgraph_context:
            try:
                pivots = hopgraph_context.get('corroboration_summary', {}).get('shared_pivots') or []
                if pivots:
                    rendered = ", ".join(p.get('pivot') for p in pivots[:3] if p.get('pivot'))
                    if rendered:
                        parts.append(f"Shared pivots: {rendered}")
                chains = hopgraph_context.get('chains') if isinstance(hopgraph_context, dict) else None
                if chains:
                    top = chains[0]
                    node_path = top.get('nodes', [])
                    if node_path:
                        rendered = " -> ".join(node_path[:5])
                        parts.append(f"HopGraph summary ({top.get('score', 0.0):.2f}): {rendered}")
            except Exception:
                pass
        return " ".join(parts)

    def _build_recommendation_catalog(self, domains: Iterable[SecurityDomain]) -> List[Dict[str, Any]]:
        catalog: List[Dict[str, Any]] = []
        priority = 'standard'
        domain_map = {
            SecurityDomain.ENDPOINT: [
                ('endpoint.isolate', "Isolate affected endpoints and capture EDR telemetry.", 'high'),
                ('endpoint.forensics', "Collect forensic artifacts (memory, disk image).", 'medium'),
            ],
            SecurityDomain.NETWORK: [
                ('network.block', "Block suspicious network paths and review firewall logs.", 'high'),
                ('network.hunt', "Hunt for beaconing on other hosts.", 'medium'),
            ],
            SecurityDomain.IDENTITY: [
                ('identity.reset', "Reset credentials and enforce MFA for impacted identities.", 'critical'),
            ],
            SecurityDomain.CLOUD: [
                ('cloud.audit', "Audit cloud control plane changes & revoke risky tokens.", 'high'),
            ],
            SecurityDomain.DATA: [
                ('data.scope', "Assess data exposure scope and enable DLP tracing.", 'high'),
            ],
            SecurityDomain.EMAIL: [
                ('email.quarantine', "Quarantine related mail artifacts and run phishing hunt.", 'medium'),
            ],
            SecurityDomain.REMOTE_ACCESS: [
                ('remote.terminate', "Terminate risky RDP/VPN sessions and rotate secrets.", 'high'),
            ],
            SecurityDomain.API: [
                ('api.rotate', "Rotate API keys and tighten least-privilege scopes.", 'medium'),
            ],
        }
        for domain in domains:
            entries = domain_map.get(domain, [])
            for rec_id, action, pri in entries:
                catalog.append({
                    'id': rec_id,
                    'domain': domain.value,
                    'action': action,
                    'priority': pri,
                })
            overrides = self._recommendation_overrides.get(domain.value, [])
            for idx, action in enumerate(overrides):
                catalog.append({
                    'id': f"{domain.value}.override.{idx}",
                    'domain': domain.value,
                    'action': str(action),
                    'priority': 'custom',
                })
        if len(catalog) >= 2:
            catalog.insert(0, {
                'id': 'multidomain.escalate',
                'domain': 'multi',
                'action': "Escalate to incident response for multi-domain investigation.",
                'priority': 'critical' if len(catalog) >= 4 else 'high',
            })
        return catalog

    def _infer_mitre(self, events: Iterable[DomainEvent]) -> List[str]:
        mitre: List[str] = []
        for ev in events:
            tactics = ev.metadata.get("mitre") if isinstance(ev.metadata, dict) else None
            if isinstance(tactics, (list, tuple)):
                for tactic in tactics:
                    if tactic not in mitre:
                        mitre.append(tactic)
        return mitre

    def _capture_hopgraph(self, entity_key: str) -> Optional[Dict[str, Any]]:
        if not self._hopgraph:
            return None
        try:
            if hasattr(self._hopgraph, "snapshot"):
                return self._hopgraph.snapshot(limit=50)
            if hasattr(self._hopgraph, "identity_snapshot"):
                user = entity_key.split("|", 1)[0]
                return self._hopgraph.identity_snapshot(user)
        except Exception:
            return None
        return None

    def _hopgraph_context(
        self,
        preview: Optional[Dict[str, Any]],
        events: Iterable[DomainEvent],
        shared_pivots: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        base: Dict[str, Any] = {}
        if shared_pivots:
            base['corroboration_summary'] = {
                'shared_pivots': shared_pivots,
                'corroboration_count': len(shared_pivots),
            }
        if not self._hopgraph:
            return base or None
        candidates: List[str] = []
        primary = (preview or {}).get('primary') or {}
        host = primary.get('host', {}).get('normalized')
        user = primary.get('user', {}).get('normalized')
        ip_src = primary.get('ip_src', {}).get('normalized')
        resource = ''
        for ev in events:
            resource = str((ev.metadata or {}).get('resource') or (ev.metadata or {}).get('resource_id') or '').strip().lower()
            if resource:
                break
        if host:
            candidates.append(f'host:{host}')
        if user:
            candidates.append(f'user:{user}')
        if ip_src:
            candidates.append(f'ip:{ip_src}')
        if resource:
            candidates.append(f'resource:{resource}')
        last_error: Optional[str] = None
        for node in candidates:
            try:
                explain = self._hopgraph.explain_chain(node, max_depth=4, beam_width=6, top_k=2)
            except Exception as exc:
                last_error = str(exc)
                continue
            if not explain or not explain.get('chains'):
                continue
            trimmed: List[Dict[str, Any]] = []
            for chain in explain.get('chains', [])[:2]:
                nodes = chain.get('nodes') or []
                trimmed.append({
                    'score': chain.get('score'),
                    'nodes': nodes[:6],
                    'length': chain.get('length'),
                })
            summary = None
            if trimmed:
                summary = " -> ".join(trimmed[0].get('nodes', [])[:5])
            result = {
                'start': node,
                'chains': trimmed,
                'summary': summary,
                'captured_at': time.time(),
            }
            result.update(base)
            return result
        if last_error:
            result = {'start_candidates': candidates, 'error': last_error}
            result.update(base)
            return result
        return base or None

    def _shared_pivots(self, events: List[DomainEvent]) -> List[Dict[str, Any]]:
        pivot_map: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            source = str((ev.metadata or {}).get('source') or ev.domain.value)
            preview = resolve_entity_key(ev.entities, hash_len=self._hash_len)
            for token in self._pivot_tokens(ev.entities, ev.metadata, preview):
                entry = pivot_map.setdefault(token, {'pivot': token, 'sources': set(), 'event_ids': set(), 'domains': set()})
                entry['sources'].add(source)
                entry['event_ids'].add(ev.event_id)
                entry['domains'].add(ev.domain.value)
        rendered: List[Dict[str, Any]] = []
        for entry in pivot_map.values():
            if len(entry['event_ids']) < 2 or len(entry['domains']) < 2:
                continue
            rendered.append({
                'pivot': entry['pivot'],
                'sources': sorted(entry['sources']),
                'event_ids': sorted(entry['event_ids'])[:8],
                'domains': sorted(entry['domains']),
            })
        rendered.sort(key=lambda item: (-len(item.get('domains') or []), item.get('pivot') or ''))
        return rendered[:8]

    def _synthesize_chain(
        self,
        events: List[DomainEvent],
        domains: Iterable[SecurityDomain],
    ) -> Tuple[Optional[float], Optional[float], Optional[Dict[str, Any]]]:
        if not events:
            return None, None, None
        if get_factor_synthesis_engine is None or factor_category_for_name is None or Factor is None:
            return None, None, None
        engine = get_factor_synthesis_engine()
        if engine is None:
            return None, None, None
        factors: List[Factor] = []
        for ev in events:
            names = ev.factors or []
            for name in names:
                try:
                    category = factor_category_for_name(name)
                except Exception:
                    category = FactorCategory.META
                try:
                    ts = datetime.fromtimestamp(ev.timestamp)
                except Exception:
                    ts = datetime.utcnow()
                weight = float(ev.score or 0.0)
                weight = max(0.05, min(1.0, weight if weight > 0 else 0.4))
                metadata = ev.metadata if isinstance(ev.metadata, dict) else {}
                factors.append(
                    Factor(
                        name=name,
                        category=category,
                        timestamp=ts,
                        base_weight=weight,
                        metadata=metadata,
                    )
                )
        if not factors:
            return None, None, None
        context = {
            'domain_count': len(domains),
        }
        try:
            result = engine.synthesize(factors, context=context)
        except Exception:
            return None, None, None
        summary = {
            'final_score': result.final_score,
            'confidence': result.confidence,
            'contributing_factors': result.contributing_factors,
            'synergies': result.synergies_detected,
            'context_multiplier': result.context_multiplier,
            'decay_applied': result.decay_applied,
            'fp_adjustment': result.fp_adjustment,
            'explanation': result.explanation,
        }
        return result.final_score, result.confidence, summary


    # ------------------------------ admin helpers ------------------------------
    def set_ttl(self, ttl_seconds: int) -> None:
        self._ttl = max(60, int(ttl_seconds))

    def set_cleanup_interval(self, seconds: int) -> None:
        self._clean_interval = max(0, int(seconds))

    def cleanup(self) -> Dict[str, Any]:
        """Remove expired entity buckets and return stats."""
        now = time.time()
        removed_entities = 0
        removed_events = 0
        for key in list(self._events.keys()):
            bucket = self._events.get(key, [])
            fresh = [ev for ev in bucket if (now - ev.timestamp) <= self._ttl]
            removed_events += max(0, len(bucket) - len(fresh))
            if fresh:
                self._events[key] = fresh
            else:
                removed_entities += 1
                self._events.pop(key, None)
        for event_id, ev in list(self._event_index.items()):
            if (now - ev.timestamp) > self._ttl:
                self._event_index.pop(event_id, None)
        self._last_cleanup = now
        return {
            'removed_entities': removed_entities,
            'removed_events': removed_events,
            'remaining_entities': len(self._events),
            'event_index_size': len(self._event_index),
        }

    def stats(self) -> Dict[str, Any]:
        latest_chain = self._recent_chains[-1] if self._recent_chains else None
        recent_payload = []
        for chain in list(self._recent_chains)[-5:]:
            try:
                recent_payload.append({
                    'chain_id': chain.chain_id,
                    'domains': [d.value for d in chain.domains_involved],
                    'confidence': chain.confidence,
                    'recommendations': chain.recommendations[:5],
                    'generated_at': chain.generated_at,
                    'expires_at': chain.expires_at,
                })
            except Exception:
                continue
        now = time.time()
        next_cleanup = None
        if self._clean_interval:
            elapsed = now - self._last_cleanup
            next_cleanup = max(0.0, self._clean_interval - elapsed)
        ttl_remaining = None
        if latest_chain and latest_chain.expires_at:
            ttl_remaining = max(0.0, latest_chain.expires_at - now)
        return {
            'now_ts': now,
            'ttl_seconds': self._ttl,
            'cleanup_interval_seconds': self._clean_interval,
            'next_cleanup_in': next_cleanup,
            'tracked_entities': len(self._events),
            'tracked_events': len(self._event_index),
            'recent_chain_count': len(self._recent_chains),
            'total_emitted': self._total_emitted,
            'last_entity_resolution': self._last_entity_preview,
            'recent_chains': recent_payload,
            'latest_chain_id': latest_chain.chain_id if latest_chain else None,
            'latest_chain_expires_at': latest_chain.expires_at if latest_chain else None,
            'latest_chain_ttl_remaining': ttl_remaining,
        }


_GLOBAL_CORRELATOR: Optional[MultiDomainCorrelator] = None


def set_global_correlator(corr: MultiDomainCorrelator) -> MultiDomainCorrelator:
    global _GLOBAL_CORRELATOR
    _GLOBAL_CORRELATOR = corr
    return corr


def get_global_correlator() -> Optional[MultiDomainCorrelator]:
    return _GLOBAL_CORRELATOR


__all__ = [
    "MultiDomainCorrelator",
    "DomainEvent",
    "MultiDomainChain",
    "SecurityDomain",
    "get_global_correlator",
    "set_global_correlator",
]
