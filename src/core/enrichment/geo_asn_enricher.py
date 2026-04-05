import os
import json
import socket
from typing import Optional, Dict, Any

try:
    import geoip2.database as _geoipdb
except Exception:
    _geoipdb = None

# Optional ASN DB support (GeoIP2 ASN db)
_geoip_reader = None
_geoip_db_path = os.getenv('GEOIP2_DB_PATH', os.path.join('data', 'GeoLite2-City.mmdb'))
_geoip_asn_path = os.getenv('GEOIP2_ASN_DB_PATH', os.path.join('data', 'GeoLite2-ASN.mmdb'))

if _geoipdb is not None:
    try:
        if os.path.exists(_geoip_db_path):
            _geoip_reader = _geoipdb.Reader(_geoip_db_path)
    except Exception:
        _geoip_reader = None


def _is_ip(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except Exception:
            return False


def enrich_ip(ip: str) -> Dict[str, Any]:
    """Return enrichment dict with keys: country, country_code, city, latitude, longitude, asn, asn_org, asn_cidr

    Falls back gracefully when geoip2 not available or DB missing.
    """
    res: Dict[str, Any] = {
        'ip': ip,
        'country': None,
        'country_code': None,
        'city': None,
        'latitude': None,
        'longitude': None,
        'asn': None,
        'asn_org': None,
        'asn_cidr': None,
        'provider': None,
    }
    if not ip or not _is_ip(ip):
        return res
    # Try geoip2 city lookup
    if _geoip_reader is not None:
        try:
            rec = _geoip_reader.city(ip)
            if rec and rec.country:
                res['country'] = getattr(rec.country, 'name', None)
                res['country_code'] = getattr(rec.country, 'iso_code', None)
            if rec and rec.city:
                res['city'] = getattr(rec.city, 'name', None)
            if rec and hasattr(rec, 'location'):
                res['latitude'] = getattr(rec.location, 'latitude', None)
                res['longitude'] = getattr(rec.location, 'longitude', None)
        except Exception:
            # fallback below
            pass
    # Try ASN via separate reader if available
    try:
        if _geoipdb is not None and os.path.exists(_geoip_asn_path):
            try:
                with _geoipdb.Reader(_geoip_asn_path) as asn_reader:
                    a = asn_reader.asn(ip)
                    res['asn'] = getattr(a, 'autonomous_system_number', None)
                    res['asn_org'] = getattr(a, 'autonomous_system_organization', None)
                    res['asn_cidr'] = getattr(a, 'network', None)
            except Exception:
                pass
    except Exception:
        pass

    # If nothing from DBs, attempt a small public IP-to-country fallback using ipinfo.io
    if not res['country']:
        try:
            token = os.getenv('IPINFO_TOKEN')
            url = f'https://ipinfo.io/{ip}/json'
            if token:
                url += f'?token={token}'
            import urllib.request as _ur
            with _ur.urlopen(url, timeout=3) as fh:
                data = json.load(fh)
                if 'country' in data:
                    res['country_code'] = data.get('country')
                if 'org' in data:
                    res['asn_org'] = data.get('org')
                if 'loc' in data:
                    latlon = data.get('loc').split(',')
                    if len(latlon) >= 2:
                        try:
                            res['latitude'] = float(latlon[0])
                            res['longitude'] = float(latlon[1])
                        except Exception:
                            pass
        except Exception:
            pass

    return res


__all__ = ['enrich_ip']
