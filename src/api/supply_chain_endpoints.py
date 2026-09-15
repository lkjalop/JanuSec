from fastapi import APIRouter, Body, HTTPException
from typing import Dict, Any
from src.domains.supply_chain.package_integrity import verify_package
from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime
from src.domains.iam.correlation import correlate_events_time_window
from src.domains.iam.privilege_escalation import reevaluate_on_iam_event
import time

router = APIRouter(prefix='/api/v1/sbom', tags=['sbom'])


@router.post('/verify_package')
def api_verify_package(payload: Dict[str, Any] = Body(...)):
    try:
        # Basic validation to avoid internal errors from malformed payloads
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail='invalid_payload')
        name = payload.get('name')
        if name is None:
            # require name for deterministic behavior
            raise HTTPException(status_code=422, detail='name_required')
        result = verify_package(payload)
        # Persist supply-chain event into tenant runtime for correlation
        try:
            # tenant may be provided in payload or default
            tenant = payload.get('tenant') or payload.get('tenant_id') or 'global'
            runtime = get_server_runtime_state(None)
            tmap = runtime.tenants.setdefault(tenant, {})
            ev = {'ts': time.time(), 'payload': payload, 'result': result, 'eventTime': payload.get('ts', time.time())}
            recent = tmap.setdefault('recent_supply_chain_events', [])
            recent.append(ev)
            if len(recent) > 200:
                del recent[:-200]
            try:
                persist_tenant_runtime(runtime, tenant)
            except Exception:
                pass
            # correlate with any stored IAM evals/events
            iam_events = tmap.get('iam_eval_results', [])
            correlated = []
            if iam_events:
                correlated = correlate_events_time_window(iam_events, [ev], window_seconds=300)
                # If correlated, trigger reevaluation for affected principals
                for c in correlated:
                    try:
                        iam_ev = c.get('iam')
                        # run reevaluation for actor/target
                        reevaluate_on_iam_event(iam_ev or {}, runtime=runtime, tenant_id=tenant)
                    except Exception:
                        pass
                # record metrics for correlated matches (best-effort)
                try:
                    from src.api import iam_metrics
                    try:
                        iam_metrics.incr_eval(tenant, 'correlated_supply')
                    except Exception:
                        pass
                except Exception:
                    pass
                # persist correlation results
                corr_store = tmap.setdefault('supply_iam_correlation', [])
                corr_store.extend(correlated)
                if len(corr_store) > 200:
                    del corr_store[:-200]
                # unified correlation store
                uni = tmap.setdefault('iam_correlations', [])
                for c in correlated:
                    try:
                        uni.append({'type': 'supply', 'ts': time.time(), 'pair': c})
                    except Exception:
                        pass
                if len(uni) > 500:
                    del uni[:-500]
                # persist tenant runtime after correlation
                try:
                    persist_tenant_runtime(runtime, tenant)
                except Exception:
                    pass
        except Exception:
            pass
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
