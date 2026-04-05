"""Simple evidence reference store for attaching snippets to events.

This module provides a minimal file-backed store for references to
evidence (pcap fragments, netflow snippet ids). In production this would
be an object storage or DB-backed service.
"""
from pathlib import Path
import json
from typing import Dict, Any

BASE = Path('data/evidence')
BASE.mkdir(parents=True, exist_ok=True)


def save_evidence_ref(event_id: str, evidence_type: str, blob_ref: str) -> Dict[str, Any]:
    rec = {'event_id': event_id, 'type': evidence_type, 'ref': blob_ref}
    dest = BASE / f'{event_id}_{evidence_type}.json'
    dest.write_text(json.dumps(rec))
    return rec


def get_evidence_refs(event_id: str):
    out = []
    for p in BASE.glob(f'{event_id}_*.json'):
        try:
            out.append(json.loads(p.read_text()))
        except Exception:
            continue
    return out
