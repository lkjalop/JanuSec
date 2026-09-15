from __future__ import annotations
import json
import logging
import os
from typing import Dict, List, Optional
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

logger = logging.getLogger(__name__)


def _data_dir() -> str:
    base = os.getenv('MITRE_DATA_DIR') or os.path.join(os.getcwd(), 'data', 'mitre')
    os.makedirs(base, exist_ok=True)
    return base


def load_local_techniques() -> Dict[str, Dict]:
    path = os.path.join(_data_dir(), 'techniques.json')
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        logger.exception('Failed loading local mitre techniques')
        return {}


def save_local_techniques(data: Dict[str, Dict]) -> None:
    path = os.path.join(_data_dir(), 'techniques.json')
    try:
        with open(path + '.tmp', 'w', encoding='utf-8') as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(path + '.tmp', path)
    except Exception:
        logger.exception('Failed saving local mitre techniques')


def normalize_stix(objects: List[Dict]) -> Dict[str, Dict]:
    """Normalize STIX objects to a simple technique map keyed by technique id.

    Only extracts a minimal set of fields: id, name, platforms, tactics, detection, mitigations, description.
    """
    out: Dict[str, Dict] = {}
    with tracer.start_as_current_span('mitre.normalize_stix'):
        for obj in (objects or []):
            try:
                typ = obj.get('type')
                if typ not in ('attack-pattern', 'tool', 'malware'):
                    continue
                tid = obj.get('id') or obj.get('external_references', [{}])[0].get('external_id')
                if not tid:
                    continue
                name = obj.get('name')
                desc = obj.get('description') or obj.get('x_mitre_data_sources') or ''
                platforms = obj.get('x_mitre_platforms') or []
                tactics = []
                try:
                    killchain = obj.get('kill_chain_phases') or obj.get('x_mitre_detection')
                    if isinstance(killchain, list):
                        tactics = [p.get('phase_name') for p in killchain if isinstance(p, dict) and p.get('phase_name')]
                except Exception:
                    pass
                detection = obj.get('x_mitre_detection') or ''
                mitigations = obj.get('x_mitre_mitigations') or obj.get('x_mitre_permissions_required') or ''
                out[tid] = {
                    'id': tid,
                    'name': name,
                    'description': desc,
                    'platforms': platforms,
                    'tactics': tactics,
                    'detection': detection,
                    'mitigations': mitigations,
                    'raw': obj,
                }
            except Exception:
                logger.exception('Failed normalizing stix object')
                continue
    return out


def ingest_from_stix(stix_json: Dict) -> Dict[str, Dict]:
    with tracer.start_as_current_span('mitre.ingest_from_stix') as span:
        objs = stix_json.get('objects') if isinstance(stix_json, dict) else None
        normalized = normalize_stix(objs or [])
        span.set_attribute('mitre.count', len(normalized))
        save_local_techniques(normalized)
        return normalized
