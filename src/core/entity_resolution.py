"""Entity resolution utilities: canonicalize common identifiers.

Minimal, centralized helpers to normalize entities across connectors and
correlation paths. These functions are pure and safe to import anywhere.
"""
from __future__ import annotations

import re
from typing import Optional

_WS = re.compile(r"\s+")


def canonicalize_user(user: str | None) -> Optional[str]:
    if not user:
        return None
    u = user.strip().lower()
    u = _WS.sub(" ", u)
    # Drop domain prefixes/suffixes commonly seen in usernames
    if "@" in u:
        u = u.split("@", 1)[0]
    if "\\" in u:
        u = u.split("\\", 1)[-1]
    return u or None


def canonicalize_host(host: str | None) -> Optional[str]:
    if not host:
        return None
    h = host.strip().lower()
    h = _WS.sub(" ", h)
    # Remove trailing dots and collapse multiple dots
    h = h.rstrip(".")
    h = re.sub(r"\.+", ".", h)
    return h or None


def canonicalize_domain(domain: str | None) -> Optional[str]:
    # Alias to host canonicalization for now
    return canonicalize_host(domain)


def canonicalize_ip(ip: str | None) -> Optional[str]:
    if not ip:
        return None
    s = ip.strip().lower()
    # Normalize IPv6 shorthand and collapse zeros (lightweight)
    s = re.sub(r"^0+", "0", s)
    # Remove surrounding brackets often present in logs
    s = s.strip("[]")
    return s or None


def canonicalize_hash(h: str | None) -> Optional[str]:
    if not h:
        return None
    s = h.strip().lower()
    s = re.sub(r"[^0-9a-f]", "", s)
    return s or None


def canonical_entity_id(domain: str | None, entity: str | None) -> Optional[str]:
    """Compute a simple canonical entity id combining domain and entity.

    Example: ("identity", "Alice@EXAMPLE") -> "identity:alice"
    """
    d = canonicalize_domain(domain)
    e = canonicalize_user(entity) if (d or "").startswith("identity") else (entity or "")
    e = (e or "").strip().lower()
    if not (d and e):
        return None
    return f"{d}:{e}"


__all__ = [
    "canonicalize_user",
    "canonicalize_host",
    "canonicalize_domain",
    "canonicalize_ip",
    "canonicalize_hash",
    "canonical_entity_id",
]
"""Shared entity resolution helpers.

Normalizes canonical entity fields (user, host, ip) and produces stable
fingerprints so backend correlation and frontend displays stay aligned.
"""

from dataclasses import dataclass, asdict
import hashlib
import ipaddress
from typing import Any, Dict, Iterable, List, Tuple


_ENTITY_FIELDS = {
    'user': 'identity',
    'username': 'identity',
    'principal': 'identity',
    'account': 'identity',
    'host': 'endpoint',
    'hostname': 'endpoint',
    'device': 'endpoint',
    'endpoint': 'endpoint',
    'ip': 'network',
    'ip_src': 'network',
    'src_ip': 'network',
    'source_ip': 'network',
    'ip_dst': 'network',
    'dst_ip': 'network',
    'destination_ip': 'network',
}

_PRIMARY_ALIAS = {
    'user': ('user', 'username', 'principal', 'account'),
    'host': ('host', 'hostname', 'device', 'endpoint'),
    'ip_src': ('ip_src', 'src_ip', 'source_ip', 'ip'),
    'ip_dst': ('ip_dst', 'dst_ip', 'destination_ip'),
}


@dataclass(frozen=True)
class EntityRecord:
    """Represents a normalized entity value."""

    entity_type: str
    raw: str
    normalized: str
    fingerprint: str
    occurrences: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalize_value(entity_type: str, value: Any) -> str:
    text = '' if value is None else str(value).strip()
    if not text:
        return ''
    if entity_type == 'network':
        try:
            return str(ipaddress.ip_address(text))
        except Exception:
            return text.lower()
    return text.lower()


def _fingerprint(entity_type: str, normalized: str, length: int = 12) -> str:
    digest = hashlib.sha1(normalized.encode('utf-8')).hexdigest()  # noqa: S324 (sha1 ok for labels)
    return f"{entity_type}:{digest[:length]}"


def build_resolution_map(
    field_values: Dict[str, Iterable[Any]] | None,
    *,
    limit: int = 25,
    hash_len: int = 12
) -> Dict[str, List[Dict[str, Any]]]:
    """Return normalized entity map for a batch: {field: [EntityRecord]}."""
    if not field_values:
        return {}
    resolved: Dict[str, Dict[str, EntityRecord]] = {}
    for field, values in field_values.items():
        if not values:
            continue
        entity_type = _ENTITY_FIELDS.get(field.lower())
        if not entity_type:
            continue
        store = resolved.setdefault(field, {})
        for value in values:
            normalized = _normalize_value(entity_type, value)
            if not normalized:
                continue
            fp = _fingerprint(entity_type, normalized, length=hash_len)
            rec = store.get(fp)
            if rec:
                store[fp] = EntityRecord(
                    entity_type=rec.entity_type,
                    raw=rec.raw,
                    normalized=rec.normalized,
                    fingerprint=rec.fingerprint,
                    occurrences=rec.occurrences + 1,
                )
            else:
                store[fp] = EntityRecord(
                    entity_type=entity_type,
                    raw=str(value),
                    normalized=normalized,
                    fingerprint=fp,
                    occurrences=1,
                )
    out: Dict[str, List[Dict[str, Any]]] = {}
    for field, recs in resolved.items():
        ordered = sorted(recs.values(), key=lambda r: (-r.occurrences, r.normalized))
        out[field] = [r.to_dict() for r in ordered[:limit]]
    return out


def aggregate_resolution(
    batch_map: Dict[str, Dict[str, List[Dict[str, Any]]]] | None,
    *,
    limit: int = 40
) -> Dict[str, Any]:
    """Aggregate per-batch resolution maps into a session summary."""
    if not batch_map:
        return {'hash': {'algo': 'sha1', 'length': 12}, 'per_batch': {}, 'session': {}}
    per_batch: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    session_index: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for batch_id, field_map in batch_map.items():
        if not field_map:
            continue
        trimmed: Dict[str, List[Dict[str, Any]]] = {}
        for field, recs in field_map.items():
            if not recs:
                continue
            trimmed[field] = recs[:limit]
            idx = session_index.setdefault(field, {})
            for rec in recs:
                fp = rec.get('fingerprint')
                if not fp:
                    continue
                existing = idx.get(fp)
                if existing:
                    existing['occurrences'] = existing.get('occurrences', 0) + int(rec.get('occurrences', 1))
                else:
                    idx[fp] = {
                        'entity_type': rec.get('entity_type'),
                        'raw': rec.get('raw'),
                        'normalized': rec.get('normalized'),
                        'fingerprint': fp,
                        'occurrences': int(rec.get('occurrences', 1)),
                    }
        if trimmed:
            per_batch[batch_id] = trimmed
    session_view: Dict[str, List[Dict[str, Any]]] = {}
    for field, idx in session_index.items():
        ordered = sorted(idx.values(), key=lambda r: (-r.get('occurrences', 0), r.get('normalized') or ''))
        session_view[field] = ordered[:limit]
    return {
        'hash': {'algo': 'sha1', 'length': 12},
        'per_batch': per_batch,
        'session': session_view,
    }


__all__ = ['EntityRecord', 'build_resolution_map', 'aggregate_resolution', 'resolve_entity_key']


def resolve_entity_key(
    entities: Dict[str, Any] | None,
    *,
    hash_len: int = 12,
) -> Dict[str, Any]:
    """Return a normalized entity fingerprint map + stable key for correlators."""
    if not entities:
        return {'key': None, 'resolved': {}, 'primary': {}}
    field_values: Dict[str, list[Any]] = {}
    for canonical, aliases in _PRIMARY_ALIAS.items():
        for alias in aliases:
            value = entities.get(alias)
            if value:
                field_values.setdefault(canonical, []).append(value)
    # Provide ip fallback when only generic 'ip' present
    if 'ip' in entities and not field_values.get('ip_src'):
        field_values.setdefault('ip_src', []).append(entities['ip'])
    resolved = build_resolution_map(field_values, limit=1, hash_len=hash_len)
    primary: Dict[str, Dict[str, Any]] = {}
    for field, recs in resolved.items():
        if not recs:
            continue
        rec = recs[0]
        primary[field] = rec
    key_parts = []
    for field in ('user', 'host', 'ip_src'):
        rec = primary.get(field)
        if rec and rec.get('fingerprint'):
            key_parts.append(rec['fingerprint'])
    key = '|'.join(key_parts)
    return {
        'key': key or None,
        'resolved': resolved,
        'primary': primary,
    }
