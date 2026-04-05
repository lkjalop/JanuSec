from __future__ import annotations

from typing import Dict, Any, List
import os

_TOR_EXIT_SET = None
_BAD_ASN_SET = None


def _load_tor_list(path: str) -> set:
    s = set()
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    s.add(ln)
    except Exception:
        pass
    return s


def _load_bad_asn(path: str) -> set:
    s = set()
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    # allow lines like 'AS12345' or '12345'
                    s.add(ln.lower().lstrip('as'))
    except Exception:
        pass
    return s


def _ensure_feeds():
    global _TOR_EXIT_SET, _BAD_ASN_SET
    if _TOR_EXIT_SET is None:
        _TOR_EXIT_SET = _load_tor_list(os.environ.get('TOR_EXIT_LIST_PATH', 'data/tor_exit_nodes.txt'))
    if _BAD_ASN_SET is None:
        _BAD_ASN_SET = _load_bad_asn(os.environ.get('BAD_ASN_LIST_PATH', 'data/bad_asns.txt'))


def detect_geo_risks(enrichment: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return list of geo risk factors based on enrichment dict containing `geo` and `asn`."""
    _ensure_feeds()
    out = []
    geo = enrichment.get('geo') or {}
    asn = enrichment.get('asn') or {}
    ip = geo.get('ip')
    country = geo.get('country')
    if ip and _TOR_EXIT_SET and ip in _TOR_EXIT_SET:
        out.append({'factor': 'geo:tor_exit_node', 'reason': f'{ip} listed as Tor exit node'})
    asn_val = asn.get('asn')
    if asn_val:
        if str(asn_val).lower().lstrip('as') in _BAD_ASN_SET:
            out.append({'factor': 'geo:known_bad_asn', 'asn': asn_val, 'reason': 'ASN listed in bad ASN feed'})
    # example high-risk country check
    high_risk = os.environ.get('GEO_HIGH_RISK_COUNTRIES', 'KP,IR,SY').split(',')
    if country and country.upper() in [c.strip().upper() for c in high_risk if c.strip()]:
        out.append({'factor': 'geo:high_risk_country', 'country': country, 'reason': 'Access from high-risk country'})
    return out


__all__ = ['detect_geo_risks']
