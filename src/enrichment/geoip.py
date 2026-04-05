from __future__ import annotations
import os, csv, ipaddress, threading
from functools import lru_cache
from typing import Optional, List, Tuple, Dict

try:  # metrics optional
    from prometheus_client import Counter  # type: ignore
    # Access REGISTRY internals only defensively (Prometheus client keeps stable names internally)
    from prometheus_client import REGISTRY  # type: ignore
except Exception:  # pragma: no cover
    Counter = REGISTRY = None  # type: ignore

_lock = threading.RLock()
# _ranges: list of tuples (start_int, end_int, country, asn)
_ranges: List[Tuple[int,int,str,str]] = []
_loaded = False
_geoip_enabled = os.getenv('GEOIP_ENABLED','1').lower() not in ('0','false','no')
# Path to CSV that may contain either start,end or CIDR notation per line
_geoip_csv = os.getenv('GEOIP_CSV','data/geoip_demo.csv')
_geo_cache_dir = os.getenv('GEO_CACHE_DIR','data/geo_cache')

def _reuse_or_create_counter(name: str, doc: str):  # pragma: no cover - tiny helper
    if not Counter or not REGISTRY:
        return None
    # Try to find existing collector to avoid duplicate registration when tests reload module
    try:
        for collector, names in getattr(REGISTRY, '_collector_to_names', {}).items():  # type: ignore[attr-defined]
            if name in names:
                return collector
        return Counter(name, doc)  # type: ignore
    except ValueError:  # duplicate race fallback
        # As last resort, scan names_to_collectors mapping
        existing = getattr(REGISTRY, '_names_to_collectors', {}).get(name)  # type: ignore[attr-defined]
        return existing
    except Exception:
        return None

if Counter:
    GEO_LOOKUPS = _reuse_or_create_counter('geoip_lookups_total','GeoIP lookups performed')  # type: ignore
    GEO_HITS = _reuse_or_create_counter('geoip_hits_total','GeoIP successful hits')  # type: ignore
else:  # pragma: no cover
    GEO_LOOKUPS = GEO_HITS = None  # type: ignore

def _load():  # pragma: no cover - IO
    global _loaded
    if _loaded or not _geoip_enabled:
        return
    rows: List[Tuple[int,int,str,str]] = []
    if not os.path.exists(_geoip_csv):
        # Don't raise here; allow tests to continue but log presence
        try:
            import logging
            logging.getLogger(__name__).warning('GEOIP CSV not found: %s', _geoip_csv)
        except Exception:
            pass
        _loaded = True
        return
    try:
        with open(_geoip_csv, 'r', encoding='utf-8') as fh:
            r = csv.reader(fh)
            for line in r:
                if not line:
                    continue
                # allow comments starting with # in first column
                if line[0].strip().startswith('#'):
                    continue
                # normalize fields
                fields = [c.strip() for c in line if isinstance(c, str)]
                if len(fields) < 3:
                    continue
                # Support formats:
                # start_ip,end_ip,country,asn
                # cidr,country,asn
                try:
                    if '/' in fields[0]:
                        # CIDR style
                        net = ipaddress.ip_network(fields[0].strip(), strict=False)
                        s_int = int(net.network_address)
                        e_int = int(net.broadcast_address)
                        country = fields[1] if len(fields) > 1 else ''
                        asn = fields[2] if len(fields) > 2 else ''
                        rows.append((s_int, e_int, country or '', asn or ''))
                    elif len(fields) >= 4:
                        start_ip, end_ip, country, asn = fields[:4]
                        s_int = int(ipaddress.ip_address(start_ip))
                        e_int = int(ipaddress.ip_address(end_ip))
                        if s_int <= e_int:
                            rows.append((s_int, e_int, country or '', asn or ''))
                    else:
                        # Skip unknown line shapes
                        continue
                except Exception:
                    continue
        rows.sort(key=lambda t: t[0])
        with _lock:
            _ranges.clear()
            _ranges.extend(rows)
    finally:
        _loaded = True

def _ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return None

@lru_cache(maxsize=2048)
def lookup_ip(ip: str) -> Optional[Dict[str,str]]:
    if not _loaded:
        _load()
    if not _ranges:
        return None
    ip_int = _ip_to_int(ip)
    if ip_int is None:
        return None
    lo, hi = 0, len(_ranges)-1
    while lo <= hi:
        mid = (lo+hi)//2
        s,e,country,asn = _ranges[mid]
        if ip_int < s:
            hi = mid - 1
        elif ip_int > e:
            lo = mid + 1
        else:
            try:
                if GEO_LOOKUPS: GEO_LOOKUPS.inc()
                if GEO_HITS: GEO_HITS.inc()
            except Exception:
                pass
            return {'country': country, 'asn': asn}
    try:
        if GEO_LOOKUPS: GEO_LOOKUPS.inc()
    except Exception:
        pass
    return None

def enrich_event(event: dict) -> None:
    if not _geoip_enabled:
        return
    for key in ('dst_ip','src_ip','ip'):
        ip = event.get(key)
        if isinstance(ip, str):
            info = lookup_ip(ip)
            if info:
                event.setdefault('geo',{})[key] = info


def initialize_geoip(force_reload: bool = False) -> None:
    """Initialize the geoip loader early (call at app startup).

    force_reload will reload ranges even if previously loaded.
    """
    global _loaded
    global _geoip_csv, _geoip_enabled
    # Re-evaluate env vars in case tests monkeypatch them
    try:
        _geoip_csv = os.getenv('GEOIP_CSV', _geoip_csv)
        _geoip_enabled = os.getenv('GEOIP_ENABLED','1').lower() not in ('0','false','no')
    except Exception:
        pass
    if force_reload:
        with _lock:
            _loaded = False
            _ranges.clear()
    _load()


__all__ = ['lookup_ip','enrich_event','initialize_geoip']

__all__ = ['lookup_ip','enrich_event']
