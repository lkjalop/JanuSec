from __future__ import annotations

import asyncio
import time
import traceback
from typing import Any, Dict

from . import get as get_action
from .dsl_schema import PlaybookSpec, PlaybookStep

try:
    from prometheus_client import Counter, Histogram  # type: ignore

    from src.api.metrics_init import REGISTRY, ensure_metrics  # type: ignore
    ensure_metrics()
    _PB_EXECUTIONS = Counter('playbook_executions_total','Playbook executions',['playbook','outcome'], registry=REGISTRY)
    _PB_ACTIONS = Counter('playbook_actions_total','Playbook action executions',['playbook','action','outcome'], registry=REGISTRY)
    _PB_ACTION_LAT = Histogram('playbook_action_latency_seconds','Playbook action latency seconds',['playbook','action'], registry=REGISTRY)
except Exception:  # pragma: no cover
    _PB_EXECUTIONS = _PB_ACTIONS = _PB_ACTION_LAT = None  # type: ignore

class PlaybookEngine:
    def __init__(self):
        self._compiled: dict[str, PlaybookSpec] = {}

    def load(self, spec: dict[str, Any]) -> PlaybookSpec:
        pb = PlaybookSpec(**spec)
        self._compiled[pb.id] = pb
        return pb

    async def run(self, playbook_id: str, context: dict[str, Any]) -> dict[str, Any]:
        pb = self._compiled.get(playbook_id)
        if not pb:
            raise ValueError(f'playbook_not_found:{playbook_id}')
        overall = {'playbook': pb.id, 'steps': [], 'started_at': time.time()}
        outcome = 'success'
        for step in pb.steps:
            step_result = await self._run_step(pb, step, context)
            overall['steps'].append(step_result)
            if step_result.get('error') and not step.continue_on_error:
                outcome = 'error'
                break
        overall['finished_at'] = time.time()
        overall['outcome'] = outcome
        if _PB_EXECUTIONS:
            try: _PB_EXECUTIONS.labels(playbook=pb.id, outcome=outcome).inc()
            except Exception: pass
        return overall

    async def _run_step(self, pb: PlaybookSpec, step: PlaybookStep, context: dict[str, Any]) -> dict[str, Any]:
        started = time.time()
        result: dict[str, Any] = {'id': step.id, 'action': step.action, 'ts': started}
        # Condition
        if step.when:
            try:
                if not eval(step.when, {}, {'ctx': context}):  # nosec - controlled DSL, limited globals
                    result['skipped'] = True
                    return result
            except Exception as e:
                result['error'] = f'when_eval_failed:{e}'
                return result
        action = get_action(step.action)
        try:
            run_ctx = dict(context)
            run_ctx.update(step.with_args)
            action_out = await asyncio.wait_for(action.run(run_ctx), timeout=getattr(action,'timeout_seconds',10.0))
            result['result'] = action_out
            act_outcome = 'success'
        except Exception as e:  # pragma: no cover - error path
            result['error'] = str(e)
            result['traceback'] = traceback.format_exc().splitlines()[-3:]
            act_outcome = 'error'
        result['latency'] = time.time() - started
        if _PB_ACTIONS:
            try: _PB_ACTIONS.labels(playbook=pb.id, action=step.action, outcome=act_outcome).inc()
            except Exception: pass
        if _PB_ACTION_LAT and 'skipped' not in result:
            try: _PB_ACTION_LAT.labels(playbook=pb.id, action=step.action).observe(result['latency'])
            except Exception: pass
        # Ensure metrics go through tenant-guard helper when possible
        try:
            from src.api.metrics_tenant_helper import emit_labels_with_guard
        except Exception:
            emit_labels_with_guard = None
        try:
            if emit_labels_with_guard and _PB_ACTIONS:
                try:
                    labels = emit_labels_with_guard(None, {'playbook': pb.id, 'action': step.action, 'outcome': act_outcome}, None)
                    _PB_ACTIONS.labels(**labels).inc()
                except Exception:
                    try: _PB_ACTIONS.labels(playbook=pb.id, action=step.action, outcome=act_outcome).inc()
                    except Exception: pass
        except Exception:
            pass
        try:
            if emit_labels_with_guard and _PB_ACTION_LAT and 'skipped' not in result:
                try:
                    labels = emit_labels_with_guard(None, {'playbook': pb.id, 'action': step.action}, None)
                    _PB_ACTION_LAT.labels(**labels).observe(result['latency'])
                except Exception:
                    try: _PB_ACTION_LAT.labels(playbook=pb.id, action=step.action).observe(result['latency'])
                    except Exception: pass
        except Exception:
            pass
        # Propagate simple outputs back into context for later steps
        if 'result' in result and isinstance(result['result'], dict):
            for k,v in result['result'].items():
                if k not in context:  # do not override initial context keys
                    context[k] = v
        return result

ENGINE = PlaybookEngine()
__all__ = ['ENGINE','PlaybookEngine']
