from __future__ import annotations
import os
import json
import time
from typing import Dict, Any, List
from pathlib import Path

from src.graph.ingest import ingest_event
from src.graph.hopgraph import GLOBAL_HOPGRAPH


def _score_indicator(ind: Dict[str, Any]) -> float:
    # Simple heuristic scoring: IP in private range = low, public rare IPs = higher
    s = 0.0
    if ind.get('type') == 'c2' or ind.get('type') == 'beacon':
        s += 0.6
    if ind.get('file_hash'):
        s += 0.4
    if ind.get('url'):
        s += 0.3
    return min(1.0, s)


def enrich_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Perform staged enrichment producing a list of enrichment steps and a final canonical event."""
    steps: List[Dict[str, Any]] = []
    canon: Dict[str, Any] = {}
    # Stage 1: parse basic fields
    parsed = {k: raw.get(k) for k in raw}
    steps.append({'stage': 1, 'action': 'parse', 'result': parsed, 'ts': time.time()})

    # Stage 2: extract URLs and IPs from body or fields
    url = None
    if parsed.get('body'):
        for t in str(parsed.get('body')).split():
            if t.startswith('http://') or t.startswith('https://'):
                url = t; break
    if url:
        steps.append({'stage': 2, 'action': 'extract_url', 'result': {'url': url}, 'ts': time.time()})
        canon['url'] = url

    if parsed.get('dst_ip'):
        canon['dst_ip'] = parsed.get('dst_ip')

    if parsed.get('file_sha256'):
        canon['file_hash'] = parsed.get('file_sha256')

    # Stage 3: heuristic scoring
    ind = {'type': raw.get('evt_type') or raw.get('type'), 'url': canon.get('url'), 'file_hash': canon.get('file_hash')}
    score = _score_indicator(ind)
    steps.append({'stage': 3, 'action': 'heuristic_score', 'result': {'score': score}, 'ts': time.time()})

    # Stage 4: map to ingest_event canonical fields
    mapped = {}
    if parsed.get('from'):
        mapped['src_host'] = parsed.get('from')
    if parsed.get('to'):
        mapped['dst_email'] = parsed.get('to')
    if canon.get('dst_ip'):
        mapped['dst_ip'] = canon.get('dst_ip')
    if canon.get('file_hash'):
        mapped['file_hash'] = canon.get('file_hash')
    if canon.get('url'):
        mapped['url'] = canon.get('url')
    mapped['score'] = score
    steps.append({'stage': 4, 'action': 'map_to_canonical', 'result': mapped, 'ts': time.time()})

    # Optionally ingest into HopGraph as evidence
    try:
        try:
            from src.core.graph.hopgraph_utils import safe_upsert_node
        except Exception:
            safe_upsert_node = None
        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH
        except Exception:
            GLOBAL_HOPGRAPH = None
        # If we have a canonical file_hash, prefer safe upsert to preserve attrs
        fh = mapped.get('file_hash')
        if GLOBAL_HOPGRAPH is not None and safe_upsert_node is not None and fh:
            try:
                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', fh, attrs=mapped, source='enr_pipeline')
                steps.append({'stage': 5, 'action': 'ingest', 'result': {'status': 'ok'}, 'ts': time.time()})
            except Exception as e:
                steps.append({'stage': 5, 'action': 'ingest', 'result': {'status': 'error', 'err': str(e)}, 'ts': time.time()})
        else:
            try:
                try:
                    from src.core.graph.hopgraph_utils import safe_upsert_node
                except Exception:
                    safe_upsert_node = None
                if mapped.get('type') == 'file_hash' and mapped.get('id') and safe_upsert_node is not None:
                    try:
                        safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', mapped.get('id'), attrs=mapped.get('attrs') or {}, source='enr_pipeline')
                    except Exception:
                        try:
                            ingest_event(mapped, source='enr_pipeline')
                        except Exception:
                            pass
                else:
                    try:
                        ingest_event(mapped, source='enr_pipeline')
                    except Exception:
                        pass
                steps.append({'stage': 5, 'action': 'ingest', 'result': {'status': 'ok'}, 'ts': time.time()})
            except Exception as e:
                steps.append({'stage': 5, 'action': 'ingest', 'result': {'status': 'error', 'err': str(e)}, 'ts': time.time()})
    except Exception as e:
        steps.append({'stage': 5, 'action': 'ingest', 'result': {'status': 'error', 'err': str(e)}, 'ts': time.time()})

    return {'canonical': mapped, 'steps': steps}


def enrich_batch(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows:
        out.append(enrich_event(r))
    return out
