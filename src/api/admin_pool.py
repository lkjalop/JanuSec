from fastapi import APIRouter, HTTPException, Depends
from starlette.responses import JSONResponse

from src.core.event_pipeline.process_workers import pool_health, restart_pool
from src.core.event_pipeline.worker_supervisor import get_supervisor
from src.core.event_pipeline.metrics import PipelineMetrics
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/worker_pool', tags=['admin'], dependencies=[Depends(require_roles('admin'))])


@router.get('/health')
async def worker_pool_health():
    try:
        data = pool_health()
        try:
            sup = get_supervisor()
            sh = sup.health()
            data['supervisor'] = sh
            # Add per-worker last heartbeat if available via metrics
            try:
                # best-effort: collect worker heartbeat gauge labels
                pm = PipelineMetrics()
                worker_info = {}
                # if the gauge exists, attempt to read from prometheus client registry
                # but avoid hard dependency: return health from supervisor instead
                # Try to pull current metric samples from the client registry
                try:
                    from prometheus_client import REGISTRY
                    per_pid = {}
                    for metric in REGISTRY.collect():
                        name = metric.name
                        if name not in ('pipeline_worker_last_heartbeat_ts', 'pipeline_worker_tasks_inflight', 'pipeline_worker_task_latency_summary_ms', 'pipeline_worker_failure_total'):
                            continue
                        for s in metric.samples:
                            labels = dict(s.labels or {})
                            pid = labels.get('pid') or 'unknown'
                            per_pid.setdefault(pid, {})
                            per_pid[pid][name] = s.value
                    data['workers_metrics'] = per_pid
                    data['workers'] = sh.get('workers', None) or []
                except Exception:
                    data['workers'] = sh.get('workers', None) or []
            except Exception:
                pass
        except Exception:
            pass
        return JSONResponse(data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post('/restart')
async def worker_pool_restart():
    try:
        restart_pool()
        return JSONResponse({'status': 'restarted'})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
