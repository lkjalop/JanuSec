from __future__ import annotations

from typing import Dict, Any
from src.core.geoip_lookup import lookup_ip


def enrich_event_with_geoip(event: Dict[str, Any], ip_field: str = 'src_ip') -> Dict[str, Any]:
    """Lookup geoip for `ip_field` in event and attach `geo` and `asn` keys under enrichment."""
    try:
        ip = event.get(ip_field) or event.get('src') or event.get('ip')
        if not ip:
            return event
        info = lookup_ip(str(ip))
        enrichment = event.setdefault('enrichment', {})
        geo = enrichment.setdefault('geo', {})
        geo.update({
            'ip': info.get('ip'),
            'country': info.get('country'),
            'city': info.get('city'),
            'lat': info.get('latitude'),
            'lon': info.get('longitude'),
        })
        if info.get('asn'):
            enrichment.setdefault('asn', {})
            enrichment['asn'].update({'asn': info.get('asn'), 'provider': info.get('provider')})
    except Exception:
        pass
    return event


__all__ = ['enrich_event_with_geoip']
