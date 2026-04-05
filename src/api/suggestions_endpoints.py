from __future__ import annotations
import re
import json
from collections import Counter
from typing import Any
from fastapi import APIRouter, HTTPException, Request
from typing import Optional
import database_adapter
import hashlib
import time
import os
from pathlib import Path


router = APIRouter()

# Lightweight heuristics to extract domain tokens from supplied rows
_DOMAIN_RE = re.compile(r"\b((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})\b")


@router.post('/api/v1/suggestions/domains')
async def suggest_domains(payload: dict) -> dict:
    """Return a ranked list of suggested domains from rows.

    Expects payload: { rows: [ { ... } ], limit: int }
    This is intentionally lightweight and deterministic: it scans common
    text fields and the JSON-serialized row for domain-like tokens and
    ranks by frequency.
    """
    try:
        rows = payload.get('rows', []) if isinstance(payload, dict) else []
        limit = int(payload.get('limit', 10) if isinstance(payload, dict) else 10)
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')
    if not isinstance(rows, list):
        raise HTTPException(status_code=400, detail='rows must be an array')

    counter: Counter[str] = Counter()
    for r in rows:
        try:
            # Inspect well-known textual fields first
            text_parts = []
            if isinstance(r, dict):
                for k in ('cmdline', 'command', 'url', 'domain', 'hostname', 'host', 'dest', 'destination', 'process_name', 'filename'):
                    v = r.get(k)
                    if v:
                        text_parts.append(str(v))
                # include serialized JSON for extra context
                text_parts.append(json.dumps(r, ensure_ascii=False))
            else:
                text_parts.append(str(r))
            joined = ' '.join(text_parts)
            for m in _DOMAIN_RE.findall(joined):
                counter[m.lower()] += 1
        except Exception:
            continue

    total = sum(counter.values()) or 1
    most = []
    for d, c in counter.most_common(limit):
        most.append({'domain': d, 'count': int(c), 'score': round(float(c) / float(total), 3)})

    return {'domains': most, 'total_domains': len(counter)}



@router.post('/api/v1/suggestions/provenance')
async def store_provenance(request: Request, payload: dict) -> dict:
    """Compute a deterministic fingerprint for a row and store a human assessment.

    Payload: { row: {...}, human_assessment: { assessor: str, comment: str, tags: [..] } }
    Returns: { fingerprint: sha256, stored: True }
    """
    try:
        row = payload.get('row') if isinstance(payload, dict) else None
        ha = payload.get('human_assessment') if isinstance(payload, dict) else None
        if not row or not isinstance(row, dict):
            raise ValueError('row required')
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')

    # Build canonical string: timestamp + user + process + path + cmdline + sha256 if present
    parts = []
    ts = row.get('ts') or row.get('timestamp') or int(time.time())
    parts.append(str(ts))
    for k in ('user','username','process_name','proc','path','cmdline','command'):
        v = row.get(k) or ''
        parts.append(str(v))
    # include any provided file hash
    fh = row.get('sha256') or row.get('hash') or ''
    parts.append(str(fh))
    canon = '|'.join(parts)
    fp = hashlib.sha256(canon.encode('utf-8')).hexdigest()

    # store in app state (best-effort in-memory store)
    try:
        app = request.app
        prov = getattr(app.state, 'provenance_store', None)
        if prov is None:
            prov = {}
            app.state.provenance_store = prov
        prov_entry = prov.get(fp, {'fingerprint': fp, 'row': row, 'human_assessments': []})
        if ha and isinstance(ha, dict):
            entry = {
                'assessor': ha.get('assessor') or 'unknown',
                'comment': ha.get('comment') or '',
                'tags': ha.get('tags') or [],
                'ts': int(time.time())
            }
            prov_entry['human_assessments'].append(entry)
        prov[fp] = prov_entry
    except Exception:
        # non-fatal; continue
        pass

    # Persist to DB if available, else fallback to disk JSONL
    try:
        db = database_adapter.db_manager
        if db and getattr(db, 'adapter', None):
            # Use adapter-level method if available
            try:
                await db.adapter.store_provenance(fp, row, {
                    'assessor': ha.get('assessor') if isinstance(ha, dict) else None,
                    'comment': ha.get('comment') if isinstance(ha, dict) else None,
                    'tags': ha.get('tags') if isinstance(ha, dict) else [],
                    'playbook_ref': ha.get('playbook_ref') if isinstance(ha, dict) else None
                } if ha else None)
            except Exception:
                # best-effort, fall through to JSONL
                raise
        else:
            raise RuntimeError('db_adapter_not_connected')
    except Exception:
        try:
            target = os.getenv('PROVENANCE_PATH', 'data/provenance.json')
            target_dir = os.path.dirname(target) or 'data'
            Path(target_dir).mkdir(parents=True, exist_ok=True)
            with open(target, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(prov_entry, ensure_ascii=False) + '\n')
        except Exception:
            # ignore persistence errors
            pass

    return {'fingerprint': fp, 'stored': True}


@router.get('/api/v1/suggestions/provenance')
async def query_provenance(filter: Optional[str] = None, page: int = 1, limit: int = 50):
    """Query stored provenance entries with pagination. If filter=='assessed', return only entries with assessments."""
    assessed_only = (filter == 'assessed')

    # Prefer DB-backed query
    try:
        db = database_adapter.db_manager
        if db and getattr(db, 'adapter', None):
            res = await db.adapter.query_provenance(assessed_only, page=page, limit=limit)
            return res
    except Exception:
        # fallback to JSONL parsing
        pass

    out = []
    p = Path(os.getenv('PROVENANCE_PATH', 'data/provenance.json'))
    if not p.exists():
        return {'count': 0, 'entries': []}
    start = max(0, (page - 1) * limit)
    end = start + limit
    try:
        with p.open('r', encoding='utf-8') as fh:
            lines = fh.readlines()
            selected = lines[start:end]
            for ln in selected:
                try:
                    rec = json.loads(ln)
                    if assessed_only:
                        if rec.get('human_assessments'):
                            out.append(rec)
                    else:
                        out.append(rec)
                except Exception:
                    continue
    except Exception:
        return {'count': 0, 'entries': []}
    return {'count': len(out), 'entries': out}
