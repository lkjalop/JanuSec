from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _append(out: list[str], prefix: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            _append(out, prefix, item)
        return
    text = str(value).strip().lower()
    if not text:
        return
    out.append(f'{prefix}:{text}')


def build_correlation_keys(event: Dict[str, Any], *, extra_values: Dict[str, Any] | None = None) -> List[str]:
    """Return stable cross-domain join keys for HopGraph/correlation pivots."""
    keys: list[str] = []
    for src in (event, extra_values or {}):
        _append(keys, 'actor', src.get('actor'))
        _append(keys, 'user', src.get('user'))
        _append(keys, 'principal', src.get('principal'))
        _append(keys, 'ip', src.get('ip') or src.get('src_ip') or src.get('source_ip'))
        _append(keys, 'ip', src.get('dst_ip') or src.get('destination_ip'))
        _append(keys, 'host', src.get('host') or src.get('hostname') or src.get('device_name'))
        _append(keys, 'resource', src.get('resource_id') or src.get('resource'))
        _append(keys, 'account', src.get('account_id'))
        _append(keys, 'subscription', src.get('subscription_id'))
        _append(keys, 'interface', src.get('interface_id'))
        _append(keys, 'domain', src.get('domain'))
        _append(keys, 'ja3', src.get('ja3') or src.get('ja3_fingerprint'))
        _append(keys, 'asn', src.get('dest_asn') or src.get('src_asn') or src.get('asn'))
    # de-dupe, preserve order
    seen = set()
    ordered: list[str] = []
    for item in keys:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered

