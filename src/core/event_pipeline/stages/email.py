from __future__ import annotations

"""Email enrichment stage integrating BEC/phishing factors.

Uses the existing `src.core.hunt.lanes.email_bec` detectors via a simple
envelope shim, returning a StageResult compatible with the pipeline.
"""

from typing import Any, Dict, List
import re
import logging

from .base import StageResult, timed_stage

logger = logging.getLogger(__name__)


class _Envelope:
    def __init__(self, headers: dict[str, Any], body: str | None, event: dict[str, Any] | None):
        self.headers = headers or {}
        self.body = body or ''
        self.event = event or {}
        self.lane_factors: List[str] = []

    def add_emission(self, lane: str, factors: List[str], _meta: Any, _score: float) -> None:
        try:
            tagged = [f"{lane}:{f}" for f in factors]
            self.lane_factors.extend(tagged)
        except Exception:
            pass


@timed_stage("email_enrichment")
async def run_email_enrichment(event: dict[str, Any], ctx) -> StageResult:
    try:
        headers = event.get('headers') or {}
        body = event.get('body_preview') or ''
        env = _Envelope(headers=headers, body=body, event=event)
        # Run DKIM verification if raw message bytes present
        try:
            from src.core.enrichment.email_authenticator import DKIMVerifier
            dkim_result = None
            # Prefer raw bytes under event['raw_message_bytes'] else skip
            raw = event.get('raw_message_bytes')
            if raw and isinstance(raw, (bytes, bytearray)):
                dv = DKIMVerifier()
                dkim_result = dv.verify_message_bytes(raw)
                # attach to event for downstream stages
                event.setdefault('email_enrichment', {})
                event['email_enrichment'].setdefault('dkim', dkim_result)
        except Exception:
            dkim_result = None
        # Simple auth header checks (DMARC/SPF/DKIM)
        auth = {k.lower(): v for k, v in (headers or {}).items()}
        factors_local: List[str] = []
        def _flag_if_fail(name: str, key_candidates: List[str]) -> None:
            for k in key_candidates:
                val = auth.get(k)
                if not val:
                    continue
                v = str(val).lower()
                if 'fail' in v or 'none' in v:
                    factors_local.append(f"email:{name}_fail")
                    break
                if 'pass' in v:
                    break
        _flag_if_fail('dmarc', ['dmarc', 'authentication-results'])
        _flag_if_fail('spf', ['spf', 'authentication-results'])
        _flag_if_fail('dkim', ['dkim-signature', 'authentication-results'])
        # Extract URLs from body preview
        urls: List[str] = []
        try:
            if body:
                urls = re.findall(r"https?://[\w\-\.\?\#/=&%]+", body, flags=re.IGNORECASE)
                if urls:
                    factors_local.append('email:urls_detected')
        except Exception:
            urls = []
        try:
            from src.core.hunt.lanes import email_bec
            try:
                from src.integrations.tenant_config import load_email_config
                cfg = load_email_config()
            except Exception:
                cfg = {}
            lane = email_bec.build(cfg)
            lane(env)
        except Exception as exc:
            logger.debug("email_bec lane unavailable: %s", exc)
        factors = [f for f in env.lane_factors] + factors_local
        # Attach enrichment details into context cache for downstream use
        try:
            cache = ctx.state.get('enrichment_cache') if hasattr(ctx, 'state') else None
            if isinstance(cache, dict):
                cache.setdefault('email', {})
                cache['email'].update({'urls': urls, 'auth': {'dmarc_spf_dkim_flags': [f for f in factors_local if f.startswith('email:')]}, 'dkim': dkim_result})
        except Exception:
            pass
        # Durable HopGraph wiring for email observables (URLs/domains/attachments, auth flags)
        try:
            # Resolve core HopGraph instance
            try:
                from src.core.graph.hopgraph_core import get_core_graph  # type: ignore
                hg = get_core_graph()
            except Exception:
                try:
                    from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
                    hg = GLOBAL_HOPGRAPH
                except Exception:
                    hg = None  # type: ignore
            if hg is not None:
                # Email node id
                eid = event.get('id') or event.get('event_id') or event.get('message_id') or 'unknown'
                email_node = f"email:{str(eid).lower()}"
                # Upsert minimal attrs
                try:
                    hg.add_node_attr(email_node, type='email', subject=event.get('subject'), sender=(headers.get('from') or event.get('sender')))
                except Exception:
                    pass
                ts = event.get('timestamp')
                # Wire URLs
                for u in urls[:50]:  # cap to avoid cardinality spikes
                    try:
                        url_node = f"url:{str(u).lower()}"
                        hg.add_edge(email_node, url_node, 'contains_url', source='enriched', ts=ts)
                        # Derive domain and link url -> domain
                        dom = None
                        try:
                            # simple parse
                            dom = re.split(r"/|\\?", str(u).lower().split('://',1)[-1])[0]
                            # strip port if present
                            if ':' in dom:
                                dom = dom.split(':',1)[0]
                        except Exception:
                            dom = None
                        if dom:
                            dn = f"domain:{dom}"
                            hg.add_edge(url_node, dn, 'contacts_domain', source='enriched', ts=ts)
                    except Exception:
                        continue
                # Wire attachment hashes when present
                try:
                    attachments = None
                    # Prefer normalized email attachments when available
                    if isinstance(event.get('email'), dict):
                        attachments = event['email'].get('attachments')
                    if attachments and isinstance(attachments, list):
                        for a in attachments[:20]:
                            try:
                                sha = (a.get('sha256') or a.get('hash') or a.get('file_hash'))
                                if not sha:
                                    continue
                                hv = f"hash:{str(sha).lower()}"
                                hg.add_edge(email_node, hv, 'email_attachment', source='enriched', ts=ts)
                            except Exception:
                                continue
                except Exception:
                    pass
                # Attach auth failure factors directly to email node for explainability
                for f in factors_local:
                    try:
                        if f.startswith('email:'):
                            hg.add_node_factor(email_node, f)
                    except Exception:
                        pass
                # Attach DKIM metadata as node attrs for explainability
                try:
                    if dkim_result:
                        hg.add_node_attr(email_node, dkim=dkim_result)
                except Exception:
                    pass
        except Exception:
            # Best-effort; skip HopGraph wiring on errors
            pass
        # Simple confidence delta based on count
        delta = min(0.2, 0.03 * len(factors))
        return StageResult(name="email_enrichment", factors=factors, confidence_delta=delta, terminal=False, metadata={'count': len(factors), 'urls': urls})
    except Exception:
        return StageResult(name="email_enrichment", factors=[], confidence_delta=0.0, terminal=False, metadata={'error': 'enrichment_failed'})


__all__ = ["run_email_enrichment"]