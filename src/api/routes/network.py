from fastapi import APIRouter, Request, HTTPException, Query
import os
import time
from src.core.normalize import normalize_domain
from src.api.runtime_state import get_server_runtime_state
from ..tenant_helpers import resolve_tenant_id

try:
    from src.core.utils.ip_utils import normalize_ip
except Exception:
    def normalize_ip(x):
        return x

router = APIRouter(prefix="/api/v1/network", tags=["network"])

@router.post('/ingest')
async def ingest_network(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    src_ip = data.get('src_ip')
    dst_ip = data.get('dst_ip')
    if src_ip:
        src_ip = normalize_ip(src_ip)
    if dst_ip:
        dst_ip = normalize_ip(dst_ip)
    protocol = (data.get('protocol') or 'tcp').lower()
    bytes_out = int(data.get('bytes_out') or 0)
    domain = normalize_domain(data.get('domain')) if data.get('domain') else None
    hg = getattr(request.app, 'GLOBAL_HOPGRAPH', None)
    if hg is None:
        return {'status': 'mock'}
    ts = time.time()
    try:
        if src_ip:
            hg.add_node_attr(f'ip:{src_ip}', type='ip')
        if dst_ip:
            hg.add_node_attr(f'ip:{dst_ip}', type='ip')
        if src_ip and dst_ip:
            hg.add_edge(f'ip:{src_ip}', f'ip:{dst_ip}', 'net_flow', source='network', attrs={'protocol': protocol, 'bytes_out': bytes_out, 'ts': ts})
        if domain and src_ip:
            hg.add_node_attr(f'domain:{domain}', type='domain')
            hg.add_edge(f'ip:{src_ip}', f'domain:{domain}', 'dns_a', source='network', attrs={'ts': ts})
        # Emit data large extract detection (EWMA) on source node
        try:
            from src.core.detectors.data_large_extract import check_and_emit as check_data_large
        except Exception:
            check_data_large = None
        try:
            if check_data_large and src_ip:
                # source node id used by detector
                src_node = f'ip:{src_ip}'
                check_data_large(hg, src_node, bytes_out)
        except Exception:
            pass
        if bytes_out > 5_000_000:
            # Represent large transfer as a meta node for correlation/factor tests
            hg.add_node_attr('net:flow_microcluster_exfil', type='meta', bytes_out=bytes_out)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {'status': 'ok', 'ingested': 1}


@router.get('/status')
def network_status(request: Request, tenant_id: str | None = Query(default=None)) -> dict:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT', 'default')
    runtime = get_server_runtime_state(request.app)
    tmap = runtime.tenants.get(tenant) or {}
    health = tmap.get('network_connector_health') or {}
    connectors = []
    now = time.time()
    for connector_id, entry in health.items():
        last_ts = entry.get('last_event_ts')
        connectors.append(
            {
                'id': connector_id,
                'last_event_ts': last_ts,
                'seconds_since_event': (now - float(last_ts)) if last_ts else None,
                'total_ingested': entry.get('total_ingested', 0),
                'last_event_count': entry.get('last_event_count'),
            }
        )
    return {'tenant': tenant, 'connectors': connectors}
