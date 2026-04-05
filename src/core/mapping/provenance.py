"""Provenance tagging utilities.

Provides lightweight helpers to attach source adapter/feed identification and
ingestion metadata to canonical events for FP triage and trust scoring.
"""
from __future__ import annotations

from typing import Dict, Any
import time

def tag_provenance(event: Dict[str, Any], *, source_adapter: str, source_id: str | None = None, batch_id: str | None = None) -> Dict[str, Any]:
    prov = {
        'adapter': source_adapter,
        'source_id': source_id,
        'batch_id': batch_id,
        'ingest_ts': time.time()
    }
    # Preserve existing provenance if any while updating keys
    existing = event.get('provenance') if isinstance(event.get('provenance'), dict) else {}
    merged = {**existing, **prov}
    event['provenance'] = merged
    return event

__all__ = ['tag_provenance']