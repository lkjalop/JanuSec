"""Simple IP -> ASN lookup helper for tests and lightweight enrichment.

Features:
- seed_mapping(dict[ip_prefix_or_ip]->ASN) to provide deterministic test mappings
- lookup_asn(ip) returns 'ASxxxxx' or None
- seed_from_ips(list_of_ips) will attempt to map IPs via seeded map, else use heuristic (last-octet -> AS)
"""
from __future__ import annotations
from typing import Optional, Dict, Iterable
import ipaddress

# Simple in-memory map: exact IP or CIDR -> ASN string
_mapping: Dict[str, str] = {}

def seed_mapping(d: Dict[str, str]) -> None:
    """Seed explicit IP/CIDR -> ASN mapping. Keys may be IP or CIDR strings."""
    global _mapping
    for k,v in (d or {}).items():
        try:
            _mapping[str(k)] = str(v).upper()
        except Exception:
            continue

def clear_mapping() -> None:
    global _mapping
    _mapping.clear()

def _match_seed(ip: str) -> Optional[str]:
    # exact match
    if ip in _mapping:
        return _mapping[ip]
    # CIDR match
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    for k,v in _mapping.items():
        try:
            if '/' in k:
                net = ipaddress.ip_network(k, strict=False)
                if addr in net:
                    return v
        except Exception:
            continue
    return None

def lookup_asn(ip: str) -> Optional[str]:
    """Return ASN string (e.g. 'AS65001') for given IP when known, else None.
    Uses seeded mappings first; falls back to simple deterministic heuristic.
    """
    if not ip:
        return None
    ip = str(ip).strip()
    try:
        got = _match_seed(ip)
        if got:
            return got
    except Exception:
        pass
    # Heuristic fallback: use last octet to synthesize a stable ASN for private ranges
    try:
        addr = ipaddress.ip_address(ip)
        # prefer mapping for RFC1918 ranges
        if addr.is_private:
            # map last octet to AS number in 65000-65999
            parts = ip.split('.')
            if len(parts) == 4 and parts[-1].isdigit():
                n = int(parts[-1])
                asn = 65000 + (n % 1000)
                return f"AS{asn}"
    except Exception:
        pass
    return None

def seed_from_ips(ips: Iterable[str]) -> Dict[str, str]:
    """Return a map of ip->asn seeded by lookup_asn (best-effort).
    Also registers the found ASNs in the returned mapping.
    """
    out = {}
    for ip in ips or []:
        try:
            asn = lookup_asn(str(ip))
            if asn:
                out[str(ip)] = asn
        except Exception:
            continue
    return out

__all__ = ['seed_mapping','clear_mapping','lookup_asn','seed_from_ips']
