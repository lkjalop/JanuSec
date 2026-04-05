from __future__ import annotations
import os, time, threading, json
from typing import Dict, Any, List, Optional

_lock = threading.RLock()
_ring: List[Dict[str,Any]] = []
_max = int(os.getenv('CORR_EDGE_BUFFER_MAX','20000') or 20000)
_ml_export_enabled = os.getenv('CORR_ML_EXPORT','1') not in ('0','false','False')
_ml_export_path = os.getenv('CORR_ML_EXPORT_PATH','data/correlation_chains_buffer.jsonl')
try:
    # ingestion-level normalizer: map legacy aliases to canonical names
    from src.core.threat_modeling.ingestion_normalizer import normalize_factors
except Exception:
    def normalize_factors(x):
        return list(x)

def emit_edge(annotation: Dict[str,Any]) -> None:
    """Store a correlation edge annotation in an in-memory ring buffer.

    Expected schema keys (not strictly enforced for flexibility):
      edge_type: str   (e.g., 'campaign','sequence','suppression','pmi')
      rule_id: str     (identifier for rule / correlator)
      ts: float        (epoch seconds)
      entities: list[str]  (entity or pivot identifiers)
      input_factors: list[str]
      output_factor: str | None
      delta: float     (positive or negative confidence impact)
      meta: dict       (auxiliary fields: support, window, pmi, suppression_ratio, etc.)
    """
    if 'ts' not in annotation:
        annotation['ts'] = time.time()
    with _lock:
        _ring.append(annotation)
        if len(_ring) > _max:
            # Drop oldest slice (~10%) to avoid O(n) shift per item
            drop = max(1, _max//10)
            del _ring[:drop]
    if _ml_export_enabled:
        try:
            # Normalize factors before persisting/exporting so historical
            # buffer entries move to canonical names for new writes.
            ann = dict(annotation)
            if 'input_factors' in ann and isinstance(ann['input_factors'], (list,tuple)):
                ann['input_factors'] = normalize_factors(ann['input_factors'])
            # also normalize pivot metadata and output_factor when present
            try:
                if isinstance(ann.get('meta'), dict) and 'pivot' in ann['meta']:
                    ann['meta'] = dict(ann['meta'])
                    ann['meta']['pivot'] = normalize_factors([ann['meta']['pivot']])[0]
            except Exception:
                pass
            if 'output_factor' in ann and isinstance(ann['output_factor'], str):
                ann['output_factor'] = normalize_factors([ann['output_factor']])[0]

            # Append-only JSONL (best-effort); tolerate failures silently
            with open(_ml_export_path,'a',encoding='utf-8') as fh:
                fh.write(json.dumps(ann, ensure_ascii=False) + '\n')
        except Exception:
            pass

def recent_edges(limit: int = 500) -> List[Dict[str,Any]]:
    with _lock:
        # Return a shallow copy; also normalize any in-memory entries on read
        out = []
        for ann in list(_ring[-limit:]):
            try:
                a = dict(ann)
                if 'input_factors' in a and isinstance(a['input_factors'], (list,tuple)):
                    a['input_factors'] = normalize_factors(a['input_factors'])
                if isinstance(a.get('meta'), dict) and 'pivot' in a['meta']:
                    a = dict(a)
                    a['meta'] = dict(a.get('meta') or {})
                    try:
                        a['meta']['pivot'] = normalize_factors([a['meta']['pivot']])[0]
                    except Exception:
                        pass
                if 'output_factor' in a and isinstance(a['output_factor'], str):
                    a['output_factor'] = normalize_factors([a['output_factor']])[0]
                out.append(a)
            except Exception:
                out.append(ann)
        return out

__all__ = ['emit_edge','recent_edges']