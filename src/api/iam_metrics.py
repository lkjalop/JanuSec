from typing import Optional
import logging
try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover - prometheus optional
    Counter = None  # type: ignore
    Gauge = None  # type: ignore

LOGGER = logging.getLogger('iam_metrics')

# Counters and gauges (best-effort registration)
try:
    iam_evals_total = Counter('iam_evals_total', 'Total IAM evaluations', ['tenant', 'verdict']) if Counter is not None else None
    iam_feedback_total = Counter('iam_feedback_total', 'Total IAM feedback', ['tenant', 'verdict']) if Counter is not None else None
    iam_escalation_risk = Gauge('iam_escalation_risk', 'Last escalation risk for principal', ['tenant', 'principal']) if Gauge is not None else None
except Exception:
    iam_evals_total = None
    iam_feedback_total = None
    iam_escalation_risk = None


def incr_eval(tenant: str, verdict: str) -> None:
    try:
        if iam_evals_total:
            iam_evals_total.labels(tenant=str(tenant), verdict=str(verdict)).inc()
    except Exception:
        LOGGER.exception('incr_eval')


def incr_feedback(tenant: str, verdict: str) -> None:
    try:
        if iam_feedback_total:
            iam_feedback_total.labels(tenant=str(tenant), verdict=str(verdict)).inc()
    except Exception:
        LOGGER.exception('incr_feedback')


def set_escalation_risk(tenant: str, principal: str, value: float) -> None:
    try:
        if iam_escalation_risk:
            iam_escalation_risk.labels(tenant=str(tenant), principal=str(principal)).set(float(value))
    except Exception:
        LOGGER.exception('set_escalation_risk')
