from __future__ import annotations
"""Enrichment lookup registry for LOOKUP.<name>(field) functions.

Provide a simple registry where functions can be registered and called by name.
Functions accept (event, field_path_list) and return scalar values.
"""
from typing import Callable, Any, List

_registry: dict[str, Callable[[dict, List[str]], Any]] = {}


def register(name: str):
    def deco(f: Callable[[dict, List[str]], Any]):
        _registry[name] = f
        return f
    return deco


def lookup_func(name: str, event: dict, field: list[str]):
    f = _registry.get(name)
    if not f:
        raise KeyError(f'unknown lookup {name}')
    return f(event, field)

# Example: ASN rarity stub
@register('asn_rarity')
def _asn_rarity(event: dict, field: list[str]):
    # Field typically src.ip; for demo return a synthetic score based on last octet
    try:
        from ipaddress import ip_address
        v = event
        for p in field:
            v = v.get(p) if isinstance(v, dict) else None
        if not v:
            return 0.0
        ip = str(v)
        last = int(ip.split('.')[-1]) if '.' in ip else 0
        return min(1.0, (last % 100) / 100)
    except Exception:
        return 0.0

__all__ = ['register','lookup_func']
