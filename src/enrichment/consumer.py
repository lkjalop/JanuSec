"""Consume enrichment events from EVENT_QUEUE and integrate into HopGraph & CRQ.

This consumer is best-effort and safe to enable via env ENABLE_ENRICHMENT_CONSUMER=1.
It will create simple nodes for hashes and emit FAIR-shadow observations via compute_fair_row.
"""
from __future__ import annotations
import asyncio
import os
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Test / runtime override for HopGraph instance (injected in tests for determinism)
_HOPGRAPH_OVERRIDE = None

def set_hopgraph_override(hg):
    global _HOPGRAPH_OVERRIDE
    _HOPGRAPH_OVERRIDE = hg

def clear_hopgraph_override():
    global _HOPGRAPH_OVERRIDE
    _HOPGRAPH_OVERRIDE = None

try:
    from src.api.runtime_state import EVENT_QUEUE
except Exception:
    EVENT_QUEUE = None

try:
    from src.crq.fair_shadow import compute_fair_row, persist_shadow_observation
except Exception:
    compute_fair_row = None
    persist_shadow_observation = None
try:
    from src.enrichment.geo_integration import enrich_event_with_geo
except Exception:
    enrich_event_with_geo = None


async def _process_event(ev: Dict[str, Any]):
    try:
        if not isinstance(ev, dict):
            return
        # Attempt lightweight geo/asn enrichment for IP-bearing events
        try:
            if enrich_event_with_geo is not None:
                # safe-call; pass app-like object if available in event meta
                app = ev.get('_app') or ev.get('meta', {}).get('app')
                # many callers enqueue raw events without app; attempt to import runtime app
                if app is None:
                    try:
                        from src.api.app import app as _app
                        app = _app
                    except Exception:
                        app = None
                if app is not None:
                    try:
                        enrich_event_with_geo(app, ev)
                    except Exception:
                        # do not fail the consumer on enrichment errors
                        pass
        except Exception:
            pass
        typ = ev.get('type')
        # EPSS high for hash
        if typ == 'enrichment:epss_high' and ev.get('hash'):
            sha = ev.get('hash')
            tenant = (ev.get('meta') or {}).get('tenant') or (ev.get('meta') or {}).get('owner')
            host = (ev.get('meta') or {}).get('host') or (ev.get('meta') or {}).get('hostname')
            # Ingest into HopGraph if available
            # Allow tests to inject a HopGraph instance deterministically
            if _HOPGRAPH_OVERRIDE is not None:
                GLOBAL_HOPGRAPH = _HOPGRAPH_OVERRIDE
            else:
                # First try to honor any test-time module stub placed in sys.modules
                import sys
                mod = sys.modules.get('src.graph.hopgraph')
                if mod is not None:
                    try:
                        logger.debug('sys.modules["src.graph.hopgraph"] repr=%r has_GLOBAL=%s', mod, hasattr(mod, 'GLOBAL_HOPGRAPH'))
                    except Exception:
                        pass
                    
                    # If test installed a module-like object, accept it as the hopgraph
                    # instance when it directly implements ingest/upsert interfaces.
                    if hasattr(mod, 'ingest_event') or hasattr(mod, 'upsert_node') or hasattr(mod, 'merge_node_attrs'):
                        GLOBAL_HOPGRAPH = mod
                    else:
                        GLOBAL_HOPGRAPH = getattr(mod, 'GLOBAL_HOPGRAPH', None)
                else:
                    try:
                        from src.graph.hopgraph import GLOBAL_HOPGRAPH
                    except Exception:
                        try:
                            from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH
                        except Exception:
                            GLOBAL_HOPGRAPH = None
            if GLOBAL_HOPGRAPH is not None and hasattr(GLOBAL_HOPGRAPH, 'ingest_event'):
                try:
                    logger.debug('Resolved GLOBAL_HOPGRAPH of type %s', type(GLOBAL_HOPGRAPH))
                except Exception:
                    pass
                # create a simple node event, include geo/asn attributes when present
                node_event = {'node_type': 'file_hash', 'hash': sha, 'factors': ['intel:epss_high'], 'ts': time.time()}
                # attach attrs from enrichment if present
                attrs = {}
                try:
                    if 'geo' in ev and isinstance(ev['geo'], dict):
                        g = ev['geo']
                        attrs['geo'] = {'country': g.get('country'), 'city': g.get('city'), 'latitude': g.get('latitude'), 'longitude': g.get('longitude')}
                    if 'asn' in ev and isinstance(ev['asn'], dict):
                        a = ev['asn']
                        attrs['asn'] = {'asn': a.get('asn'), 'org': a.get('asn_org'), 'cidr': a.get('asn_cidr')}
                    if attrs:
                        node_event['attrs'] = attrs
                except Exception:
                    pass
                try:
                    # Prefer a safe upsert helper to centralize merge semantics
                    try:
                        from src.core.graph.hopgraph_utils import safe_upsert_node
                    except Exception:
                        safe_upsert_node = None
                    fh = sha
                    if safe_upsert_node is not None:
                        try:
                            try:
                                logger.debug('About to call safe_upsert_node on %r with attrs=%r', GLOBAL_HOPGRAPH, node_event.get('attrs'))
                            except Exception:
                                pass
                            safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', fh, attrs=node_event.get('attrs') or {}, source='enrichment_consumer')
                        except Exception as e:
                            try:
                                logger.exception('safe_upsert_node raised; falling back to ingest_event')
                            except Exception:
                                pass
                            try:
                                GLOBAL_HOPGRAPH.ingest_event(node_event, source='enrichment_consumer')
                            except Exception:
                                try:
                                    logger.exception('GLOBAL_HOPGRAPH.ingest_event fallback failed')
                                except Exception:
                                    pass
                                pass
                    else:
                        try:
                            GLOBAL_HOPGRAPH.ingest_event(node_event, source='enrichment_consumer')
                        except Exception:
                            pass
                    # Also, defensive: if tests or other modules placed a different
                    # object into sys.modules['src.graph.hopgraph'].GLOBAL_HOPGRAPH
                    # (test-time injection races), try to call into that instance too
                    try:
                        import sys as _sys
                        _mod = _sys.modules.get('src.graph.hopgraph')
                        if _mod is not None:
                            _alt = getattr(_mod, 'GLOBAL_HOPGRAPH', None)
                            if _alt is not None and _alt is not GLOBAL_HOPGRAPH:
                                try:
                                    if hasattr(_alt, 'upsert_node'):
                                        _alt.upsert_node(node_event.get('hash') or canonical_node_id('file_hash', fh), node_type='file_hash', attrs=node_event.get('attrs'), source='enrichment_consumer_mirror')
                                    elif hasattr(_alt, 'merge_node_attrs'):
                                        _alt.merge_node_attrs(node_event.get('hash') or canonical_node_id('file_hash', fh), node_event.get('attrs') or {}, source='enrichment_consumer_mirror')
                                    elif hasattr(_alt, 'ingest_event'):
                                        _alt.ingest_event(node_event, source='enrichment_consumer_mirror')
                                except Exception:
                                    pass
                    except Exception:
                        pass
                except Exception:
                    pass
                # Optionally emit shared-attribute edges (asn_shared / geo_shared)
                try:
                    # emit an asn_shared edge if ASN present
                    if 'asn' in ev and isinstance(ev['asn'], dict) and ev['asn'].get('asn'):
                        asn_val = ev['asn'].get('asn')
                        edge = {'type': 'asn_shared', 'asn': asn_val, 'node_hash': sha, 'ts': time.time()}
                        if hasattr(GLOBAL_HOPGRAPH, 'emit_edge'):
                            try:
                                GLOBAL_HOPGRAPH.emit_edge(edge)
                            except Exception:
                                pass
                        # mirror to alternate hopgraph instance if present
                        try:
                            import sys as _sys
                            _mod = _sys.modules.get('src.graph.hopgraph')
                            if _mod is not None:
                                _alt = getattr(_mod, 'GLOBAL_HOPGRAPH', None)
                                if _alt is not None and _alt is not GLOBAL_HOPGRAPH and hasattr(_alt, 'emit_edge'):
                                    try:
                                        _alt.emit_edge(edge)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                    # emit a geo_shared edge if country present
                    if 'geo' in ev and isinstance(ev['geo'], dict) and ev['geo'].get('country'):
                        country = ev['geo'].get('country')
                        edge = {'type': 'geo_shared', 'country': country, 'node_hash': sha, 'ts': time.time()}
                        if hasattr(GLOBAL_HOPGRAPH, 'emit_edge'):
                            try:
                                GLOBAL_HOPGRAPH.emit_edge(edge)
                            except Exception:
                                pass
                        # mirror to alternate hopgraph instance if present
                        try:
                            import sys as _sys
                            _mod = _sys.modules.get('src.graph.hopgraph')
                            if _mod is not None:
                                _alt = getattr(_mod, 'GLOBAL_HOPGRAPH', None)
                                if _alt is not None and _alt is not GLOBAL_HOPGRAPH and hasattr(_alt, 'emit_edge'):
                                    try:
                                        _alt.emit_edge(edge)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                except Exception:
                    pass
            
            # Create FAIR-shadow observation using compute_fair_row if available
            try:
                # Resolve compute/persist functions; prefer module attribute lookup so
                # test-time assignments on the module are honored.
                import sys
                mod = sys.modules.get(__name__)
                compute_fn = getattr(mod, 'compute_fair_row', None)
                persist_fn = getattr(mod, 'persist_shadow_observation', None)
                if not callable(compute_fn) or not callable(persist_fn):
                    try:
                        from src.crq.fair_shadow import compute_fair_row as _cf, persist_shadow_observation as _ps
                        if not callable(compute_fn):
                            compute_fn = _cf
                        if not callable(persist_fn):
                            persist_fn = _ps
                    except Exception:
                        # leave as-is; fallbacks handled below
                        pass

                try:
                    logger.debug('TEST_DEBUG: resolved compute_fn=%s persist_fn=%s', compute_fn, persist_fn)
                except Exception:
                    pass

                if callable(compute_fn):
                    row = {'canonical': {'file_hash': sha, 'host': host}, 'reputation': {'epss_score': ev.get('score', 0.0)}, 'meta': {}}
                    obs = compute_fn(row)
                    obs.update({'hash': sha, 'source': 'enrichment:epss', 'ts': time.time()})
                    if host:
                        obs['host'] = host
                    if tenant:
                        obs['tenant'] = tenant

                    if callable(persist_fn):
                        try:
                            try:
                                from src.enrichment.tfidf import classify_observation
                                cls_res = classify_observation(obs)
                                if cls_res is not None:
                                    try:
                                        prob, expl = cls_res
                                    except Exception:
                                        prob = cls_res if isinstance(cls_res, float) else None
                                        expl = {}
                                    if prob is not None:
                                        obs['tfidf_score'] = float(prob)
                                    if expl:
                                        total = sum(abs(v) for v in expl.values()) or 1.0
                                        norm = {k: float(v) / total for k, v in expl.items()}
                                        obs['score_explanation'] = {'raw': expl, 'normalized': norm}
                            except Exception:
                                pass

                            try:
                                logger.debug('TEST_DEBUG: about to call persist_fn with obs: %s', obs)
                                persist_fn(obs)
                                logger.debug('TEST_DEBUG: persist_fn call completed')
                            except Exception as e:
                                try:
                                    logger.debug('TEST_DEBUG: persist_fn raised exception: %s', e)
                                except Exception:
                                    pass
                                pass
                        except Exception:
                            pass

                    # Also write a tenant-linked copy to aid persona rollups
                    try:
                        link_fn = getattr(__import__('src.crq.fair_shadow', fromlist=['']), 'link_observation_to_tenant', None)
                        # allow test-time override on module as well
                        link_fn = globals().get('link_observation_to_tenant') or link_fn
                        if tenant and callable(link_fn):
                            link_fn(obs, tenant)
                    except Exception:
                        pass
            except Exception:
                pass
        # KEV candidate
        if typ == 'enrichment:kev_candidate' and ev.get('cve'):
            cve = ev.get('cve')
            try:
                from src.incidents.aggregator import GLOBAL_INCIDENTS
                if GLOBAL_INCIDENTS is not None and hasattr(GLOBAL_INCIDENTS, 'add_recommendation'):
                    try:
                        GLOBAL_INCIDENTS.add_recommendation({'cve': cve, 'note': 'KEV candidate detected', 'ts': time.time()})
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        logger.exception('Failed to process enrichment event')


async def _consumer_loop(interval: int = 1):
    if not EVENT_QUEUE:
        return
    short = os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}
    if short:
        interval = 1
    while True:
        try:
            try:
                ev = await EVENT_QUEUE.dequeue(timeout=0.05)
            except Exception:
                ev = None
            if ev:
                await _process_event(ev)
        except Exception:
            logger.exception('enrichment consumer loop error')
        await asyncio.sleep(interval)


def register_enrichment_consumer(app):
    try:
        if os.getenv('ENABLE_ENRICHMENT_CONSUMER','0').lower() in {'1','true','yes'}:
            app.add_event_handler('startup', lambda: asyncio.create_task(_consumer_loop()))
    except Exception:
        logger.exception('Failed to register enrichment consumer')
