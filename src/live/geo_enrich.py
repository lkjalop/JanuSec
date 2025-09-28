"""GeoIP / ASN enrichment stub.

Provides a pluggable interface; current implementation returns deterministic
fake ASN and country codes based on hashing the IP (sufficient for heuristic
rarity / outbound context classification in MVP).
"""
from __future__ import annotations
import hashlib, os
from typing import Dict

_PROVIDER = os.getenv('GEO_PROVIDER','stub').lower()

def _stub(ip: str) -> Dict[str,str]:
    h = hashlib.sha256(ip.encode()).digest()
    asn = 10000 + (h[0] % 5000)
    country = chr(65 + (h[1] % 26)) + chr(65 + (h[2] % 26))
    return {'asn': f'AS{asn}', 'country': country}

_MM_READER = None
def _maxmind(ip: str) -> Dict[str,str]:
    global _MM_READER
    db_path = os.getenv('MAXMIND_DB_PATH','GeoLite2-City.mmdb')
    if _MM_READER is None:
        try:
            import geoip2.database  # type: ignore
            if os.path.exists(db_path):
                _MM_READER = geoip2.database.Reader(db_path)  # type: ignore
        except Exception:
            return _stub(ip)
    if _MM_READER is None:
        return _stub(ip)
    try:
        city = _MM_READER.city(ip)  # type: ignore
        country = (city.country.iso_code or 'UN') if getattr(city,'country',None) else 'UN'
    except Exception:
        country = 'UN'
    # ASN DB optional
    asn = 'AS0'
    try:
        asn_path = os.getenv('MAXMIND_ASN_DB_PATH','GeoLite2-ASN.mmdb')
        import geoip2.database  # type: ignore
        if os.path.exists(asn_path):
            reader_asn = geoip2.database.Reader(asn_path)  # type: ignore
            asn_rec = reader_asn.asn(ip)  # type: ignore
            asn = f"AS{asn_rec.autonomous_system_number}" if getattr(asn_rec,'autonomous_system_number',None) else asn
    except Exception:
        pass
    return {'asn': asn, 'country': country}

def enrich(ip: str | None) -> Dict[str,str]:
    if not ip:
        return {}
    if _PROVIDER == 'maxmind':
        return _maxmind(ip)
    # Placeholder for ipinfo provider
    return _stub(ip)