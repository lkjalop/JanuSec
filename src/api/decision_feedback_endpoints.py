"""Decision-level feedback endpoint.

Allows labeling a decision (true_positive / false_positive / needs_review) and
optionally applies calibration votes to factors using weights_calibrator.
"""
from __future__ import annotations

from typing import Any, List
from fastapi import APIRouter, HTTPException, Header, Request
from .tenant_helpers import resolve_tenant_id
from pydantic import BaseModel
from src.config import risk_loader
try:
    from prometheus_client import Counter  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

router = APIRouter(prefix='/api/v1/feedback', tags=['Feedback'])

_DECISION_FEEDBACK_COUNTER = None
try:
    if Counter is not None:
        _DECISION_FEEDBACK_COUNTER = Counter('decision_feedback_votes_total','Total decision feedback votes', ['label','factor'])  # type: ignore
except Exception:
    _DECISION_FEEDBACK_COUNTER = None

# Best-effort metric for labels received (per-label, per-tenant)
try:
    from core.metrics.registry import metric_counter
    _LABEL_RECEIVED = metric_counter('labeling', 'received', 'Labels received', labels=['label','tenant'])
except Exception:
    _LABEL_RECEIVED = None

VALID_LABELS = {'true_positive','false_positive','needs_review'}

class DecisionLabelPayload(BaseModel):  # type: ignore[misc]
    decision_id: str
    label: str
    factors: List[str] | None = None  # explicit factors (if not stored)
    evidence: str | None = None
    query_template: str | None = None
    apply_calibration: bool = True
    calibration_mode: str | None = None  # optional future extension (e.g., 'logistic')


class BatchDecisionPayload(BaseModel):  # type: ignore[misc]
    items: List[DecisionLabelPayload]


def _is_authorized(x_api_key: str | None) -> bool:
    return bool(x_api_key)

@router.post('/decision', summary='Label a decision and update factor weights', operation_id='feedback_label_decision')
async def label_decision(payload: DecisionLabelPayload, request: Request, x_api_key: str | None = Header(None), x_ab_test_id: str | None = Header(None, alias='X-AB-Test-Id'), x_ab_variant: str | None = Header(None, alias='X-AB-Variant')) -> dict[str, Any]:
    if not _is_authorized(x_api_key):
        raise HTTPException(status_code=403, detail='forbidden')
    label = payload.label.strip().lower()
    if label not in VALID_LABELS:
        raise HTTPException(status_code=400, detail='invalid_label')
    decision_id = (payload.decision_id or '').strip()
    if not decision_id:
        raise HTTPException(status_code=400, detail='missing_decision_id')
    # Derive vote polarity: true_positive -> strengthen factors (+1), false_positive -> weaken (-1)
    vote = 0
    if label == 'true_positive':
        vote = 1
    elif label == 'false_positive':
        vote = -1
    # Resolve factors: payload factors override; else attempt repository lookup (best-effort)
    factors: List[str] = []
    if isinstance(payload.factors, list) and payload.factors:
        factors = [str(f) for f in payload.factors if isinstance(f, str)]
    else:  # best-effort lookup
        try:
            from repositories import decision_repo  # type: ignore
            rec = await decision_repo.get_decision(decision_id)
            if rec and isinstance(rec.get('factors'), list):
                factors = [str(f) for f in rec.get('factors') if isinstance(f, str)]
        except Exception:
            factors = []
    calibrated: dict[str, float] = {}
    if vote != 0 and payload.apply_calibration and factors:
        try:
            from src.core.calibration.weights_calibrator import apply_vote  # type: ignore
            for f in factors:
                # Apply vote (idempotent); capture updated weight
                w_cfg = apply_vote(f, vote)
                calibrated[f] = float(w_cfg.get(f)) if f in w_cfg else 0.0
                try:
                    if _DECISION_FEEDBACK_COUNTER is not None:
                        _DECISION_FEEDBACK_COUNTER.labels(label=label, factor=f).inc()
                except Exception:
                    pass
        except Exception:
            pass
    # Best-effort audit emit
    try:
        from src.api.server import audit_emit  # type: ignore
        audit_emit('decision_label', None, {'decision_id': decision_id, 'label': label, 'vote': vote, 'factors': factors})
    except Exception:
        pass
    # Persist label to decision_labels table (for metrics)
    try:
        from src.repositories import decision_labels_repo
        # Try to infer event_id from decision repo if available
        event_id = None
        try:
            from repositories import decision_repo
            rec = await decision_repo.get_decision(decision_id)
            if rec:
                event_id = rec.get('event_id') or rec.get('id')
        except Exception:
            event_id = None
        # Optional A/B test headers
        test_id = None
        variant = None
        try:
            # running in FastAPI route; read from environment or request headers if available
            # fallback: no AB info
            pass
        except Exception:
            pass
        try:
            # derive tenant id from request
            try:
                tenant = resolve_tenant_id(request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
            except Exception:
                tenant = None
            try:
                evidence = payload.evidence if hasattr(payload, 'evidence') else None
                query_template = payload.query_template if hasattr(payload, 'query_template') else None
                await decision_labels_repo.insert_label(event_id or decision_id, decision_id, label, tenant, x_ab_test_id or test_id, x_ab_variant or variant, evidence, query_template)
                # increment label received metric
                try:
                    if _LABEL_RECEIVED is not None:
                        lbls = {'label': label, 'tenant': str(tenant) if tenant else ''}
                        _LABEL_RECEIVED.labels(label=lbls['label'], tenant=lbls['tenant']).inc()
                        try:
                            from core.metrics.publisher import emit_metric_event
                            emit_metric_event('label.received', lbls, 1)
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass
    except Exception:
        pass
    return {'status': 'ok', 'decision_id': decision_id, 'label': label, 'vote': vote, 'calibrated_weights': calibrated, 'factors': factors, 'risk_config_hash': risk_loader.config_hash()}

@router.post('/decisions/batch', summary='Batch label decisions and update factor weights')
async def batch_label_decisions(payload: BatchDecisionPayload, x_api_key: str | None = Header(None)) -> dict[str, Any]:
    if not _is_authorized(x_api_key):
        raise HTTPException(status_code=403, detail='forbidden')
    results: list[dict[str, Any]] = []
    # Iterate items and reuse label_decision logic but inline to avoid double auth
    for item in payload.items:
        item_res: dict[str, Any] = {'decision_id': item.decision_id, 'label': item.label}
        try:
            label = item.label.strip().lower()
            if label not in VALID_LABELS:
                item_res['status'] = 'error'; item_res['error'] = 'invalid_label'; results.append(item_res); continue
            decision_id = (item.decision_id or '').strip()
            if not decision_id:
                item_res['status'] = 'error'; item_res['error'] = 'missing_decision_id'; results.append(item_res); continue
            vote = 0
            if label == 'true_positive': vote = 1
            elif label == 'false_positive': vote = -1
            # Resolve factors
            factors: List[str] = []
            if isinstance(item.factors, list) and item.factors:
                factors = [str(f) for f in item.factors if isinstance(f, str)]
            else:
                try:
                    from repositories import decision_repo  # type: ignore
                    rec = await decision_repo.get_decision(decision_id)
                    if rec and isinstance(rec.get('factors'), list):
                        factors = [str(f) for f in rec.get('factors') if isinstance(f, str)]
                except Exception:
                    factors = []
            calibrated = {}
            if vote != 0 and item.apply_calibration and factors:
                try:
                    from src.core.calibration.weights_calibrator import apply_vote  # type: ignore
                    for f in factors:
                        w_cfg = apply_vote(f, vote)
                        calibrated[f] = float(w_cfg.get(f)) if f in w_cfg else 0.0
                        try:
                            if _DECISION_FEEDBACK_COUNTER is not None:
                                _DECISION_FEEDBACK_COUNTER.labels(label=label, factor=f).inc()
                        except Exception:
                            pass
                except Exception:
                    pass
            # audit
            try:
                from src.api.server import audit_emit  # type: ignore
                audit_emit('decision_label_batch', None, {'decision_id': decision_id, 'label': label, 'vote': vote, 'factors': factors})
            except Exception:
                pass
            item_res.update({'status':'ok','vote': vote, 'calibrated_weights': calibrated, 'factors': factors})
        except Exception as e:
            item_res['status'] = 'error'; item_res['error'] = str(e)
        results.append(item_res)
    # summary
    summary = {'total': len(results), 'ok': sum(1 for r in results if r.get('status')=='ok'), 'errors': sum(1 for r in results if r.get('status')!='ok')}
    return {'status':'ok','summary': summary, 'results': results, 'risk_config_hash': risk_loader.config_hash()}

__all__ = ['router']
