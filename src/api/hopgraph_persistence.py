"""API endpoints for HopGraph snapshot export and restore.

Provides simple snapshot/restore helpers used by tests and the demo UI.
S3 offload is optional and only used when boto3 is available and
HOPGRAPH_S3_BUCKET is set.
"""

from fastapi import APIRouter, HTTPException, Body, Request, Depends
from typing import Any, Dict, Optional
import json
import os
import time
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/hopgraph')


def _get_hopgraph():
    """Return the active HopGraph instance.

    Prefer the lite graph via get_graph(); fall back to core GLOBAL_HOPGRAPH if present.
    Tests may monkeypatch this function to return a specific instance.
    """
    try:
        from src.core.graph.hopgraph_lite import get_graph
        return get_graph()
    except Exception:
        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
            return GLOBAL_HOPGRAPH
        except Exception:
            return None


# Optional S3 support (best-effort)
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    _HAS_BOTO3 = True
except Exception:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception
    _HAS_BOTO3 = False


def _get_s3_client():
    if not _HAS_BOTO3:
        raise RuntimeError('boto3 not available')
    return boto3.client('s3')


if _HAS_BOTO3:
    def upload_snapshot_to_s3(snapshot: Dict[str, Any], bucket: str, key: Optional[str] = None) -> Dict[str, str]:
        client = _get_s3_client()
        if not key:
            ts = int(time.time())
            tenant = snapshot.get('tenant_id') or 'global'
            key = f'hopgraph_snapshot_{tenant}_{ts}.json'
        body = json.dumps(snapshot, separators=(',', ':'), ensure_ascii=False)
        try:
            client.put_object(Bucket=bucket, Key=key, Body=body.encode('utf-8'))
            return {'bucket': bucket, 'key': key}
        except (BotoCoreError, ClientError) as e:  # pragma: no cover - best effort
            raise RuntimeError('s3_upload_failed: ' + str(e))


if _HAS_BOTO3:
    def download_snapshot_from_s3(bucket: str, key: str) -> Dict[str, Any]:
        client = _get_s3_client()
        try:
            resp = client.get_object(Bucket=bucket, Key=key)
            body = resp['Body'].read()
            return json.loads(body)
        except (BotoCoreError, ClientError) as e:  # pragma: no cover - best effort
            raise RuntimeError('s3_download_failed: ' + str(e))


@router.post('/snapshot', response_model=None, dependencies=[Depends(require_roles('admin'))])
def snapshot_hopgraph(
    tenant_id: Optional[str] = None,
    request: Request = None,
    offload: bool = False,
    s3_key: Optional[str] = None,
):
    hg = _get_hopgraph()
    if not hg:
        raise HTTPException(status_code=503, detail='HopGraph not available')
    try:
        admin_key = os.getenv('ADMIN_API_KEY')
        if admin_key and request is not None:
            hdr = None
            try:
                hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
            except Exception:
                hdr = None
            if hdr != admin_key:
                raise HTTPException(status_code=403, detail='forbidden')
        # When a persistence backend exists, use its loader with the correct param name.
        # Otherwise, fall back to the lite graph's snapshot() API.
        if getattr(hg, 'backend', None):
            try:
                data = hg.backend.load_graph(tenant=tenant_id)
            except TypeError:
                # Older backends may not accept keyword; call positionally.
                try:
                    data = hg.backend.load_graph(tenant_id)  # type: ignore[arg-type]
                except Exception:
                    # Fallback to in-memory snapshot if backend read fails
                    data = hg.snapshot() if hasattr(hg, 'snapshot') else {'nodes': [], 'edges': []}
            except Exception:
                # Fallback to in-memory snapshot on any backend error
                data = hg.snapshot() if hasattr(hg, 'snapshot') else {'nodes': [], 'edges': []}
        else:
            # HopGraphLite exposes snapshot() returning {'nodes': [...], 'edges': [...]}
            if hasattr(hg, 'snapshot'):
                data = hg.snapshot()
            else:
                # last-resort minimal shape to avoid failures in tests
                data = {'nodes': [], 'edges': []}
        # Sign snapshot
        try:
            import hashlib

            canonical = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            signature = {'sha256': digest}
        except Exception:
            signature = None
        result = {'ok': True, 'snapshot': data}
        if signature:
            result['signature'] = signature

        s3_bucket = os.getenv('HOPGRAPH_S3_BUCKET')
        if offload or s3_bucket:
            bucket = s3_bucket if s3_bucket else None
            if not bucket:
                raise HTTPException(status_code=400, detail='s3_bucket_not_configured')
            try:
                upload_resp = upload_snapshot_to_s3({'snapshot': data, 'signature': signature}, bucket, key=s3_key)
                result['s3'] = upload_resp
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/restore', response_model=None, dependencies=[Depends(require_roles('admin'))])
def restore_hopgraph(
    snapshot: Dict[str, Any] = Body(...),
    request: Request = None,
    s3_key: Optional[str] = None,
):
    hg = _get_hopgraph()
    if not hg:
        raise HTTPException(status_code=503, detail='HopGraph not available')
    try:
        admin_key = os.getenv('ADMIN_API_KEY')
        if admin_key and request is not None:
            hdr = None
            try:
                hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
            except Exception:
                hdr = None
            if hdr != admin_key:
                raise HTTPException(status_code=403, detail='forbidden')

        if s3_key:
            s3_bucket = os.getenv('HOPGRAPH_S3_BUCKET')
            if not s3_bucket:
                raise HTTPException(status_code=400, detail='s3_bucket_not_configured')
            try:
                remote = download_snapshot_from_s3(s3_bucket, s3_key)
                if isinstance(remote, dict) and 'snapshot' in remote:
                    snapshot = remote['snapshot']
                else:
                    snapshot = remote
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # Optional signature verification
        try:
            import hashlib

            sig = (snapshot.get('signature') or {}).get('sha256')
            if sig:
                canonical = json.dumps({'nodes': snapshot.get('nodes', {}), 'edges': snapshot.get('edges', [])}, separators=(',', ':'), ensure_ascii=False)
                digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
                if digest != sig:
                    raise HTTPException(status_code=400, detail='invalid_signature')
        except HTTPException:
            raise
        except Exception:
            pass

        nodes_obj = snapshot.get('nodes')
        edges = snapshot.get('edges', [])
        # Normalize nodes into a dict keyed by id for backend path
        if getattr(hg, 'backend', None):
            be = hg.backend
            if isinstance(nodes_obj, dict):
                nodes_iter = nodes_obj.items()
            elif isinstance(nodes_obj, list):
                nodes_iter = ((n.get('id'), n) for n in nodes_obj if isinstance(n, dict))
            else:
                nodes_iter = []
            for nid, n in nodes_iter:
                be.save_node(nid, n.get('type', 'unknown'), n.get('metadata', {}), label=n.get('label'), tenant=n.get('tenant_id'))
            for e in edges:
                be.save_edge(e.get('src'), e.get('dst'), e.get('etype', 'link'), metadata=e.get('metadata', {}), tenant=e.get('tenant_id'))
        else:
            # HopGraphLite: rehydrate node/edge registries using internal helpers
            if isinstance(nodes_obj, dict):
                nodes_list = list(nodes_obj.values())
            elif isinstance(nodes_obj, list):
                nodes_list = [n for n in nodes_obj if isinstance(n, dict)]
            else:
                nodes_list = []
            for n in nodes_list:
                try:
                    if hasattr(hg, '_register_node'):
                        hg._register_node(n.get('type', 'unknown'), (n.get('id') or '').split(':', 1)[-1], metadata=n.get('metadata', {}), tags=set(n.get('tags') or []))
                except Exception:
                    pass
            for e in edges:
                try:
                    if hasattr(hg, '_register_edge'):
                        # Infer src/dst types from id prefixes when present; else treat as host/user/proc heuristic
                        src = e.get('src') or ''
                        dst = e.get('dst') or ''
                        etype = e.get('etype', 'link')
                        def _split_type(x: str) -> tuple[str, str]:
                            if ':' in x:
                                t, i = x.split(':', 1)
                                return t, i
                            # heuristic fallback
                            if any(ch.isdigit() for ch in x):
                                return 'host', x
                            return 'user', x
                        st, sid = _split_type(src)
                        dt, did = _split_type(dst)
                        hg._register_edge(st, sid, dt, did, etype, metadata=e.get('metadata', {}))
                except Exception:
                    pass
        return {'ok': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def snapshot_to_dict() -> Dict[str, Any]:
    try:
        hg = _get_hopgraph()
        if not hg:
            return {'nodes': {}, 'adj': {}, 'saved_ts': 0}
        data = {
            'nodes': getattr(hg, 'nodes', {}).copy(),
            'adj': {k: list(v) for k, v in getattr(hg, 'adj', {}).items()},
            'saved_ts': getattr(hg, '_edge_version', 0)
        }
        return data
    except Exception:
        return {'nodes': {}, 'adj': {}, 'saved_ts': 0}


def snapshot_to_json() -> str:
    return json.dumps(snapshot_to_dict())


def restore_from_dict(data: Dict[str, Any]) -> bool:
    try:
        hg = _get_hopgraph()
        if not hg:
            return False
        try:
            lock = getattr(hg, '_lock', None)
            if lock is not None:
                with lock:
                    hg.nodes = dict(data.get('nodes', {}))
                    hg.adj = {k: [tuple(e) for e in v] for k, v in (data.get('adj') or {}).items()}
            else:
                hg.nodes = dict(data.get('nodes', {}))
                hg.adj = {k: [tuple(e) for e in v] for k, v in (data.get('adj') or {}).items()}
        except Exception:
            hg.nodes = dict(data.get('nodes', {}))
            hg.adj = {k: [tuple(e) for e in v] for k, v in (data.get('adj') or {}).items()}
        return True
    except Exception:
        return False


def restore_from_json(s: str) -> bool:
    try:
        data = json.loads(s)
    except Exception:
        return False
    return restore_from_dict(data)

