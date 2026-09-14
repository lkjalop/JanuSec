from fastapi import APIRouter, HTTPException, Request
import os, json, time
from typing import Dict

router = APIRouter(prefix='/api/v1/factors', tags=['factors'])

_LABELS_PATH = os.getenv('FACTOR_LABELS_PATH', 'data/factors_labels.json')

def _ensure_labels_dir():
    try:
        d = os.path.dirname(_LABELS_PATH)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
    except Exception:
        pass

def _persist_labels(runtime) -> None:
    if runtime is None:
        return
    try:
        _ensure_labels_dir()
        tmp = _LABELS_PATH + '.tmp'
        with open(tmp,'w',encoding='utf8') as fh:
            json.dump(runtime.fp_labels, fh)
        os.replace(tmp, _LABELS_PATH)
    except Exception:
        pass

def _load_labels(runtime) -> None:
    if runtime is None:
        return
    if not os.path.exists(_LABELS_PATH):
        return
    try:
        with open(_LABELS_PATH,'r',encoding='utf8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            runtime.fp_labels.update(data)
    except Exception:
        pass

@router.post('/label')
async def label_factor(payload: Dict, request: Request) -> Dict:
    """Annotate a factor (session-level) as false-positive or other label.

    Expected payload: { session_id: str, factor: str, sha256?: str, label: 'false_positive'|'benign'|'suppressed', reason?: str }
    Creates a label record keyed by composite id and persists to disk.
    """
    from src.api.runtime_state import get_server_runtime_state
    runtime = get_server_runtime_state(request.app)
    _load_labels(runtime)
    session_id = (payload.get('session_id') or '').strip()
    factor_name = (payload.get('factor') or '').strip()
    label = (payload.get('label') or 'false_positive').strip().lower()
    sha = (payload.get('sha256') or '').strip()
    if not session_id or not factor_name:
        raise HTTPException(status_code=400, detail='missing_fields')
    if label not in {'false_positive','benign','suppressed','ignore'}:
        raise HTTPException(status_code=400, detail='invalid_label')
    key_parts = [session_id, factor_name]
    if sha:
        key_parts.append(sha)
    key = '|'.join(key_parts)
    record = {
        'key': key,
        'session_id': session_id,
        'factor': factor_name,
        'sha256': sha or None,
        'label': label,
        'reason': (payload.get('reason') or '').strip() or None,
        'ts': int(time.time())
    }
    runtime.fp_labels[key] = record
    # Update per-factor FP label count metrics (best-effort)
    try:
        if label in {'false_positive','suppressed','benign'}:
            counts = getattr(runtime, 'fp_factor_fp_labels_counts', None)
            if not isinstance(counts, dict):
                counts = {}
                try:
                    runtime.fp_factor_fp_labels_counts = counts
                except Exception:
                    pass
            cur = counts.get(factor_name, 0)
            counts[factor_name] = cur + 1
            try:
                from src.core.factor_stats_manager import FACTOR_STATS  # type: ignore
                FACTOR_STATS.update_from_label([factor_name], 'fp', time.time())
            except Exception:
                pass
    except Exception:
        pass
    # Optional suppression: mark factor suppressed globally until revalidated
    try:
        if label in {'false_positive','suppressed'}:
            from src.core.factors.observe_flags import set_observed
            # set observed False for this factor to suppress (best-effort)
            set_observed(factor_name, False)
    except Exception:
        pass
    _persist_labels(runtime)
    return {'labeled': True, 'record': record}

@router.get('/labels', operation_id='factors_list_labels')
async def list_labels(session_id: str | None = None, request: Request = None) -> Dict:
    from src.api.runtime_state import get_server_runtime_state
    runtime = get_server_runtime_state(request.app if request else None)
    _load_labels(runtime)
    rows = list(runtime.fp_labels.values())
    if session_id:
        rows = [r for r in rows if r.get('session_id') == session_id]
    return {'count': len(rows), 'labels': rows}
