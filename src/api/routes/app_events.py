from fastapi import APIRouter, Request, HTTPException

router = APIRouter(prefix="/api/v1/app", tags=["app"])

@router.post('/ingest')
async def ingest_app(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    endpoint = data.get('endpoint') or data.get('path') or ''
    method = (data.get('method') or 'GET').upper()
    status = int(data.get('status') or 0)
    hg = getattr(request.app, 'GLOBAL_HOPGRAPH', None)
    if hg is None:
        return {'status': 'mock'}
    try:
        node_id = f'app:{endpoint}'
        hg.add_node_attr(node_id, type='app', method=method, status=status)
        if 'export' in endpoint.lower():
            hg.add_node_attr('app:api_abuse', type='meta', endpoint=endpoint)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {'status': 'ok'}
