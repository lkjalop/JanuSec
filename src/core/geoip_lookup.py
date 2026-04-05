from __future__ import annotations

import os
import time
from typing import Dict, Optional

_GEO_CACHE: Dict[str, Dict] = {}
_GEO_CACHE_TTL = int(os.environ.get('GEOIP_CACHE_TTL', '3600'))


def _load_reader():
    try:
        import geoip2.database
        db_path = os.environ.get('GEOLITE2_DB_PATH')
        if not db_path:
            return None
        reader = geoip2.database.Reader(db_path)
        return reader
    except Exception:
        return None


def lookup_ip(ip: str) -> Dict[str, Optional[str]]:
    now = time.time()
    ent = _GEO_CACHE.get(ip)
    if ent and ent.get('expiry', 0) > now:
        return ent['value']

    reader = _load_reader()
    out = { 'ip': ip, 'country': None, 'city': None, 'latitude': None, 'longitude': None, 'asn': None, 'provider': None }
    if reader is None:
        # best-effort: try ipinfo via env token
        token = os.environ.get('IPINFO_TOKEN')
        if token:
            try:
                import requests
                r = requests.get(f'https://ipinfo.io/{ip}/json?token={token}', timeout=2.0)
                if r.status_code == 200:
                    j = r.json()
                    out.update({
                        'country': j.get('country'),
                        'city': j.get('city'),
                        'provider': j.get('org'),
                    })
            except Exception:
                pass
        _GEO_CACHE[ip] = {'value': out, 'expiry': now + _GEO_CACHE_TTL}
        return out

    try:
        rec = reader.city(ip)
        out['country'] = getattr(rec.country, 'iso_code', None)
        out['city'] = getattr(rec.city, 'name', None)
        if rec.location:
            out['latitude'] = rec.location.latitude
            out['longitude'] = rec.location.longitude
    except Exception:
        pass

    try:
        asn_reader = None
        # Try ASN DB at GEOLITE2_ASN_PATH env var
        asn_path = os.environ.get('GEOLITE2_ASN_PATH')
        if asn_path:
            import geoip2.database
            asn_reader = geoip2.database.Reader(asn_path)
        if asn_reader:
            a = asn_reader.asn(ip)
            out['asn'] = getattr(a, 'autonomous_system_number', None)
            out['provider'] = getattr(a, 'autonomous_system_organization', None)
    except Exception:
        pass

    _GEO_CACHE[ip] = {'value': out, 'expiry': now + _GEO_CACHE_TTL}
    return out


__all__ = ['lookup_ip']
