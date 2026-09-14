from typing import Dict, Any
import logging
logger = logging.getLogger(__name__)

# Accept event dicts with keys like 'ip', 'src_ip', 'dst_ip', 'src', 'src_ip_v4'
_IP_KEYS = ('ip','src_ip','dst_ip','src','source_ip','client_ip')


def extract_ip_from_event(ev: Dict[str, Any]) -> str | None:
    if not isinstance(ev, dict):
        return None
    for k in _IP_KEYS:
        v = ev.get(k)
        if v:
            if isinstance(v, (list,tuple)):
                v = v[0]
            return str(v)
    # Try nested meta
    meta = ev.get('meta') or {}
    for k in _IP_KEYS:
        if k in meta and meta[k]:
            return str(meta[k])
    return None


def enrich_event_with_geo(app, ev: Dict[str, Any]) -> Dict[str, Any]:
    """Mutates event to attach 'geo' and 'asn' keys when IP found.

    Uses `app.state.geo_asn_enricher` if available, else no-op.
    Returns the updated event dict.
    """
    try:
        if not isinstance(ev, dict):
            return ev
        ip = extract_ip_from_event(ev)
        if not ip:
            return ev
        enricher = getattr(app.state, 'geo_asn_enricher', None) or getattr(app, 'geo_asn_enricher', None)
        # caching and metrics
        try:
            from src.core.enrichment.geo_cache import get_global_cache
            cache = get_global_cache()
        except Exception:
            cache = None
        try:
            from src.core.enrichment.asn_reputation import get_asn_reputation
        except Exception:
            get_asn_reputation = lambda a: None
        # metrics helpers (prometheus client or local counters)
        try:
            from src.api.metrics_init import get_counter
        except Exception:
            get_counter = None
        if not enricher:
            return ev
        try:
            # increment total calls
            try:
                if get_counter is not None:
                    c = get_counter('geo_enrichment_calls')
                    tenant = (ev.get('meta') or {}).get('tenant') or (ev.get('meta') or {}).get('owner') or 'unknown'
                    try:
                        c.labels(tenant=tenant).inc()
                    except Exception:
                        try:
                            c.inc()
                        except Exception:
                            pass
            except Exception:
                pass

            # lookup cache first
            info = None
            try:
                if cache is not None:
                    cached = cache.get(ip)
                    if cached is not None:
                        info = cached
                        try:
                            if get_counter is not None:
                                c = get_counter('geo_enrichment_cache_hits')
                                tenant = (ev.get('meta') or {}).get('tenant') or (ev.get('meta') or {}).get('owner') or 'unknown'
                                try:
                                    c.labels(tenant=tenant).inc()
                                except Exception:
                                    try:
                                        c.inc()
                                    except Exception:
                                        pass
                        except Exception:
                            pass
            except Exception:
                logger.exception('cache lookup failed')

            if info is None:
                info = enricher(ip)
                # store into cache
                try:
                    if cache is not None and info is not None:
                        cache.set(ip, info)
                except Exception:
                    logger.exception('cache set failed')
            if not info:
                return ev
            ev['geo'] = ev.get('geo') or {}
            ev['asn'] = ev.get('asn') or {}
            # copy canonical fields
            ev['geo'].update({
                'ip': info.get('ip'),
                'country': info.get('country'),
                'country_code': info.get('country_code'),
                'city': info.get('city'),
                'latitude': info.get('latitude'),
                'longitude': info.get('longitude'),
            })
            ev['asn'].update({
                'asn': info.get('asn'),
                'asn_org': info.get('asn_org'),
                'asn_cidr': info.get('asn_cidr'),
            })
            # attach ASN reputation when available
            try:
                rep = get_asn_reputation(info.get('asn'))
                if rep is not None:
                    ev['asn']['reputation'] = rep
            except Exception:
                try:
                    if get_counter is not None:
                        c = get_counter('geo_enrichment_failures')
                        tenant = (ev.get('meta') or {}).get('tenant') or (ev.get('meta') or {}).get('owner') or 'unknown'
                        try:
                            c.labels(tenant=tenant).inc()
                        except Exception:
                            try:
                                c.inc()
                            except Exception:
                                pass
                except Exception:
                    pass
            # metrics increment if available
            # legacy no-op metrics handled above
        except Exception:
            logger.exception('geo enrichment failed for ip %s', ip)
    except Exception:
        logger.exception('failed to enrich event with geo')
    return ev


__all__ = ['enrich_event_with_geo']
