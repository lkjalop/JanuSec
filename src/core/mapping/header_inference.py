"""Header inference & confidence scoring.

Consumes sample raw records and returns a mapping suggestion structure for UI
and downstream normalization. Uses `canonical.suggest_with_confidence` for each
field candidate. Designed for early, lightweight use (no ML dependency).
"""
from __future__ import annotations

from typing import List, Dict, Any
from .canonical import suggest_with_confidence, CANONICAL_FIELDS

def infer_headers(records: List[Dict[str, Any]], max_samples: int = 50) -> Dict[str, Dict[str, Any]]:
    """Infer canonical header mapping from sample records.

    Returns {canonical: {header: str, confidence: float, sample_values: [..]}}
    Confidence aggregated as max observed per header candidate.
    """
    samples = records[:max_samples] if max_samples > 0 else records
    candidate: Dict[str, Dict[str, Any]] = {}
    for rec in samples:
        for k, v in rec.items():
            c, conf = suggest_with_confidence(k)
            if not c or c not in CANONICAL_FIELDS:
                continue
            entry = candidate.get(c)
            if entry is None:
                entry = {'header': k, 'confidence': conf, 'sample_values': []}
                candidate[c] = entry
            else:
                # Prefer higher confidence headers; replace if stronger
                if conf > entry['confidence']:
                    entry['header'] = k
                    entry['confidence'] = conf
            if len(entry['sample_values']) < 5 and isinstance(v, (str, int, float)):
                entry['sample_values'].append(v)
    return candidate

__all__ = ['infer_headers']