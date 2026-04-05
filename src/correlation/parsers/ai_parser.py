from __future__ import annotations
from typing import Dict, Any
from ..canonical_event import CanonicalEvent


def parse_ai_record(d: Dict[str, Any]) -> CanonicalEvent:
    """Parse an AI-domain record into CanonicalEvent.

    Accepts heterogeneous inputs with common AI headers and coerces
    source_type/domain to 'ai'.
    """
    data = dict(d or {})
    # Normalize keys commonly used by frontends/CSV mapping
    if not data.get('source_type') and not data.get('domain_type'):
        data['source_type'] = 'ai'
    # pass-through for CanonicalEvent AI fields (already handled by from_dict)
    return CanonicalEvent.from_dict(data)

__all__ = ["parse_ai_record"]

