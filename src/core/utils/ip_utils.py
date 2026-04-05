"""IP normalization utilities."""
from __future__ import annotations
import ipaddress

def normalize_ip(ip: str) -> str:
    """Return canonical string for IPv4/IPv6 or original on parse failure.

    For IPv4, strips leading zeros (e.g. 010.000.000.001 -> 10.0.0.1).
    For IPv6, returns compressed, lower-case form.
    """
    if not ip or not isinstance(ip, str):
        return ip
    try:
        # ip_address handles normalization
        addr = ipaddress.ip_address(ip.strip())
        return addr.compressed.lower()
    except Exception:
        # Try naive IPv4 with dotted octets that may have leading zeros
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                parts2 = [str(int(p)) for p in parts]
                return '.'.join(parts2)
            except Exception:
                return ip
        return ip

__all__ = ['normalize_ip']
