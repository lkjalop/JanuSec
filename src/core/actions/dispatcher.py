"""Dispatch action decisions to sinks (Eclipse, Slack, Audit Log).

Sinks are optional; if not configured they no-op. Audit log is file-based
append-only for MVB; database persistence already exists for decisions but
we want a simple chronological stream of high-level decisions.
"""
from __future__ import annotations
from typing import Optional
import json, os, asyncio
from .models import ActionDecision
from .eclipse_sink import EclipseActionSink
from integrations.slack_notifier import SlackNotifier
# Adjust import: severity_rollup functionality lives under core.metrics.severity_rollup
try:
    from core.metrics import severity_rollup  # type: ignore
except Exception:  # pragma: no cover
    try:
        from core.metrics import severity_rollup as _sev_mod  # type: ignore
        severity_rollup = _sev_mod
    except Exception:
        severity_rollup = None  # fallback stub
try:
    from prometheus_client import Counter as _Counter, Histogram as _Histogram
except Exception:  # pragma: no cover
    _Counter = None  # type: ignore
    _Histogram = None  # type: ignore

if _Counter and '_decision_counter' not in globals():  # type: ignore
    _decision_counter = _Counter('decisions_total','Total decisions by type and reason',['decision','reason'])  # type: ignore
if _Histogram and '_dispatch_latency' not in globals():  # type: ignore
    _dispatch_latency = _Histogram('decision_dispatch_latency_seconds','Decision dispatch latency seconds')  # type: ignore

class ActionDispatcher:
    def __init__(self, eclipse_sink: EclipseActionSink | None, slack: SlackNotifier | None, audit_path: str):
        self.eclipse_sink = eclipse_sink
        self.slack = slack
        self.audit_path = audit_path
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        self._lock = asyncio.Lock()
        self._max_mb = float(os.getenv('LOG_MAX_MB','0'))

    def _maybe_rotate(self):
        if not self._max_mb or self._max_mb <= 0:
            return
        try:
            if not os.path.exists(self.audit_path):
                return
            size_mb = os.path.getsize(self.audit_path) / (1024*1024)
            if size_mb >= self._max_mb:
                base, ext = os.path.splitext(self.audit_path)
                import time
                rotated = f"{base}.{int(time.time())}.log"
                os.rename(self.audit_path, rotated)
        except Exception:
            pass

    async def dispatch(self, decision: ActionDecision):
        start = asyncio.get_event_loop().time()
        try:
            severity_rollup.record(decision.tenant_id, decision.severity, decision.decision, decision.reasons)
        except Exception:
            pass
        # File audit (append JSONL)
        try:
            line = json.dumps({
                'event_id': decision.event_id,
                'tenant_id': decision.tenant_id,
                'decision': decision.decision,
                'reasons': decision.reasons,
                'severity': decision.severity,
                'quality': decision.quality,
                'factors': decision.factors,
                'risk_context': decision.risk_context,
                'ts': decision.ts
            })
            async with self._lock:
                self._maybe_rotate()
                with open(self.audit_path,'a',encoding='utf-8') as f:
                    f.write(line+'\n')
        except Exception:
            pass
        # Eclipse sink for real block actions only (not sim_block)
        if decision.decision == 'block' and self.eclipse_sink:
            try:
                await self.eclipse_sink.post_action(decision)
            except Exception:
                pass
        # Slack alerts for real block / escalate (optionally include sim_block if env set)
        include_sim = os.getenv('SLACK_INCLUDE_SIM_BLOCK','0') in ('1','true','yes')
        if self.slack and (decision.decision in ('block','escalate') or (include_sim and decision.decision=='sim_block')):
            sev = 'high' if decision.decision in ('block','sim_block') else 'medium'
            factors = ','.join(decision.factors[:5])
            sev_val = f"{decision.severity:.2f}" if decision.severity is not None else '0'
            prefix = 'SIM' if decision.decision=='sim_block' else decision.decision.upper()
            text = f"[{prefix}] tenant={decision.tenant_id} sev={sev_val} factors={factors} reasons={';'.join(decision.reasons)}"
            try:
                await self.slack.send_alert(sev, text)
            except Exception:
                pass
        # Metrics counters and latency
        if '_decision_counter' in globals():  # type: ignore
            # Map sim_block to its own counter label
            if decision.reasons:
                for r in decision.reasons:
                    try:
                        _decision_counter.labels(decision=decision.decision, reason=r).inc()  # type: ignore
                    except Exception:
                        continue
            else:
                try:
                    _decision_counter.labels(decision=decision.decision, reason='none').inc()  # type: ignore
                except Exception:
                    pass
        if '_dispatch_latency' in globals():  # type: ignore
            try:
                _dispatch_latency.observe(asyncio.get_event_loop().time() - start)  # type: ignore
            except Exception:
                pass

_DISPATCHER: ActionDispatcher | None = None

def get_dispatcher() -> ActionDispatcher:
    global _DISPATCHER
    if _DISPATCHER is None:
        from .eclipse_sink import EclipseActionSink
        from integrations.slack_notifier import SlackNotifier
        webhook = os.getenv('SLACK_WEBHOOK_URL')
        slack = SlackNotifier(webhook, None, None) if webhook else None
        eclipse_url = os.getenv('ECLIPSE_OUTBOUND_URL')
        eclipse_api_key = os.getenv('ECLIPSE_OUTBOUND_API_KEY')
        sink = EclipseActionSink(eclipse_url, eclipse_api_key) if eclipse_url else None
        audit_path = os.getenv('AUDIT_LOG_PATH','artifacts/audit/decisions.log')
        _DISPATCHER = ActionDispatcher(sink, slack, audit_path)
    return _DISPATCHER
