from __future__ import annotations
import time
import os
import json
import importlib
import sys
from fastapi import APIRouter, Query, HTTPException
from typing import Optional


router = APIRouter(prefix='/api/v1/factors', tags=['factors'])


def _resolve_get_emitted():
    # Try canonical import paths first, then inspect sys.modules for emission_tracker modules
    for cand in ('src.core.factors.emission_tracker', 'core.factors.emission_tracker'):
        try:
            m = importlib.import_module(cand)
            fn = getattr(m, 'get_emitted', None)
            if callable(fn):
                try:
                    import sys as _sys
                    print(f'[DEBUG_RESOLVE_EMITTED] found get_emitted in {cand}', file=_sys.stderr)
                except Exception:
                    pass
                return fn
        except Exception:
            continue
    for name, mod in list(sys.modules.items()):
        try:
            if not mod:
                continue
            if name.endswith('emission_tracker'):
                fn = getattr(mod, 'get_emitted', None)
                if callable(fn):
                    try:
                        import sys as _sys
                        print(f'[DEBUG_RESOLVE_EMITTED] found get_emitted in module {name}', file=_sys.stderr)
                    except Exception:
                        pass
                    return fn
        except Exception:
            continue
    return None


@router.get('/emitted')
def list_emitted(since: Optional[float] = Query(None, description='Unix timestamp to filter emitted factors since')):
    """Return recent emitted factor records. If since provided, only return records with ts >= since.

    The handler resolves any in-memory `get_emitted` implementation at call time to
    avoid import-aliasing issues under pytest. If no in-memory tracker is available,
    it falls back to reading the JSONL file pointed to by `EMITTED_FACTORS_LOG_PATH`.
    """
    # First, try to resolve an in-memory tracker
    try:
        fn = _resolve_get_emitted()
        if fn is not None:
            try:
                items = fn(since)
            except TypeError:
                # Some implementations may not accept `since` param
                items = fn()
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f'get_failed: {exc}')
            # If in-memory tracker returned nothing, attempt file fallback
            try:
                if not items:
                    path = os.getenv('EMITTED_FACTORS_LOG_PATH') or os.getenv('EMITTED_FACTORS_LOG', '')
                    if path and os.path.exists(path):
                        file_items = []
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                for ln in fh:
                                    ln = ln.strip()
                                    if not ln:
                                        continue
                                    try:
                                        obj = json.loads(ln)
                                        ts = obj.get('ts')
                                        try:
                                            obj['ts'] = float(ts) if ts is not None else time.time()
                                        except Exception:
                                            obj['ts'] = time.time()
                                        file_items.append(obj)
                                    except Exception:
                                        continue
                        except Exception:
                            file_items = []
                        if file_items:
                            return {'count': len(file_items), 'items': file_items, 'entries': file_items, 'since': since, 'ts': time.time()}
            except Exception:
                pass
            return {'count': len(items), 'items': items, 'entries': items, 'since': since, 'ts': time.time()}
    except HTTPException:
        raise
    except Exception:
        # ignore and try file fallback
        pass

    # Fallback: read from JSONL file path if configured
    try:
        path = os.getenv('EMITTED_FACTORS_LOG_PATH') or os.getenv('EMITTED_FACTORS_LOG', '')
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=503, detail='tracker_unavailable')
        items = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        obj = json.loads(ln)
                        # ensure ts is numeric
                        ts = obj.get('ts')
                        try:
                            obj['ts'] = float(ts) if ts is not None else time.time()
                        except Exception:
                            obj['ts'] = time.time()
                        items.append(obj)
                    except Exception:
                        continue
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f'file_read_failed: {exc}')
        # Apply since filter if provided
        if since is not None:
            try:
                items = [i for i in items if (i.get('ts') or 0) >= float(since)]
            except Exception:
                pass
        return {'count': len(items), 'items': items, 'entries': items, 'since': since, 'ts': time.time()}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail='tracker_unavailable')


__all__ = ['router']
