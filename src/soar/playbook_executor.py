"""Minimal Playbook Executor

Provides a lightweight DSL for advisory / SOAR-like actions with idempotent
execution logging. Designed as an interim layer before full DSL engine.

YAML Schema (list of steps):
- id: tag_alert
  action: tag
  params:
    tags: ["suspicious", "lateral" ]
- id: note_context
  action: note
  params:
    text: "Possible lateral movement chain detected"
- id: notify_sec
  action: slack
  params:
    channel: "#sec-alerts"
    message: "{{event.id}} escalated (confidence={{confidence}})"
  depends_on: [tag_alert]

Idempotency:
- Each executed action writes a JSONL record into action_log/DATE/<execution_id>.log
- Re-running with same execution_id skips already completed step IDs.

Extensibility:
- Future: enrich, ticket, containment actions; conditional expressions; rollback semantics.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    from prometheus_client import Counter
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

ACTION_LOG_ROOT = Path('action_log')

@dataclass
class PlayStep:
    id: str
    action: str
    params: dict[str, Any]
    depends_on: list[str]

class PlaybookExecutor:
    def __init__(self, slack_notifier=None, ai_provider=None):
        self.slack_notifier = slack_notifier
        self.ai_provider = ai_provider  # optional external enrichment adapter
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__, '_init', False):
            return
        if Counter:
            try:
                self.__class__.pb_actions_total = Counter('playbook_actions_total','Playbook actions executed', ['action','status'])
            except Exception:
                pass
        self.__class__._init = True

    def load_yaml(self, path: str | Path) -> list[PlayStep]:
        data = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
        steps: list[PlayStep] = []
        if not isinstance(data, list):
            raise ValueError('Playbook YAML must be a list of steps')
        for entry in data:
            step_id = entry.get('id') or f"step_{len(steps)}"
            steps.append(PlayStep(
                id=step_id,
                action=entry.get('action','unknown'),
                params=entry.get('params',{}) or {},
                depends_on=list(entry.get('depends_on',[]) or [])
            ))
        return steps

    def _log_path(self, execution_id: str) -> Path:
        day = time.strftime('%Y-%m-%d')
        p = ACTION_LOG_ROOT / day
        p.mkdir(parents=True, exist_ok=True)
        return p / f"{execution_id}.log"

    def _load_completed(self, log_path: Path) -> set[str]:
        done: set[str] = set()
        if log_path.exists():
            for line in log_path.read_text(encoding='utf-8').splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get('status') == 'success':
                        done.add(rec.get('id'))
                except Exception:
                    pass
        return done

    def _write_record(self, log_path: Path, record: dict[str, Any]):
        with log_path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')

    def _template(self, text: str, context: dict[str, Any]) -> str:
        def repl(m):
            key = m.group(1).strip()
            return str(context.get(key,''))
        return re.sub(r'\{\{([^}]+)\}\}', repl, text)

    async def execute(self, execution_id: str, steps: list[PlayStep], context: dict[str, Any]) -> dict[str, Any]:
        log_path = self._log_path(execution_id)
        completed = self._load_completed(log_path)
        summary = {'execution_id': execution_id, 'steps': []}
        for step in steps:
            if step.id in completed:
                summary['steps'].append({'id': step.id, 'action': step.action, 'skipped': 'already_completed'})
                continue
            if any(dep not in completed for dep in step.depends_on):
                summary['steps'].append({'id': step.id, 'action': step.action, 'skipped': 'dependency_pending'})
                continue
            status = 'success'
            detail: dict[str, Any] = {}
            try:
                # Conditional gating by required factor presence
                required_factor = step.params.get('require_factor')
                if required_factor and required_factor not in context.get('factors', []):
                    status = 'skipped'
                    detail['reason'] = 'required_factor_missing'
                elif step.action == 'tag':
                    detail['tags'] = step.params.get('tags', [])
                elif step.action == 'note':
                    txt = step.params.get('text','')
                    detail['note'] = self._template(txt, context)
                elif step.action == 'slack':
                    channel = step.params.get('channel','#sec-alerts')
                    msg = self._template(step.params.get('message',''), context)
                    if self.slack_notifier and status != 'skipped':
                        try:
                            await self.slack_notifier.send(channel, msg)
                        except Exception as e:
                            detail['slack_error'] = str(e)
                            status = 'error'
                    detail['channel'] = channel
                    detail['message'] = msg
                elif step.action == 'enrich':
                    if self.ai_provider and status != 'skipped':
                        try:
                            payload = {k: context.get(k) for k in ('event_id','confidence','factors')}
                            enr = await self.ai_provider.analyze(payload)
                            detail['enrichment'] = enr
                        except Exception as e:
                            detail['enrich_error'] = str(e)
                            status = 'error'
                    else:
                        status = 'skipped'
                        detail['reason'] = 'no_ai_provider'
                elif step.action == 'ticket':
                    # Write ticket JSONL stub to tickets/<date>.log
                    import json
                    import time
                    from pathlib import Path
                    troot = Path('tickets')
                    troot.mkdir(exist_ok=True)
                    rec = {
                        'event_id': context.get('event_id'),
                        'confidence': context.get('confidence'),
                        'factors': context.get('factors', [])[-10:],
                        'note': step.params.get('note'),
                        'ts': time.time()
                    }
                    with (troot / 'tickets.log').open('a', encoding='utf-8') as tf:
                        tf.write(json.dumps(rec)+'\n')
                    detail['ticket_recorded'] = True
                else:
                    status = 'error'
                    detail['error'] = 'unknown_action'
            except Exception as e:
                status = 'error'
                detail['exception'] = str(e)
            record = {'id': step.id, 'action': step.action, 'status': status, 'detail': detail, 'ts': time.time()}
            self._write_record(log_path, record)
            if getattr(self.__class__, 'pb_actions_total', None):
                try:
                    try:
                        from src.api.metrics_tenant_helper import emit_labels_with_guard
                        from src.api.server import get_server_runtime_state as _get_rt
                        labels = emit_labels_with_guard(_get_rt(None), {'action': step.action, 'status': status}, None)
                        if 'action' not in labels:
                            labels['action'] = step.action
                        if 'status' not in labels:
                            labels['status'] = status
                        self.__class__.pb_actions_total.labels(**labels).inc()
                    except Exception:
                        try:
                            self.__class__.pb_actions_total.labels(action=step.action, status=status).inc()
                        except Exception:
                            pass
                except Exception:
                    pass
            summary['steps'].append(record)
        return summary

# Simple Slack notifier adapter (async) placeholder
class SimpleSlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    async def send(self, channel: str, message: str):  # pragma: no cover - network side effect
        import aiohttp
        payload = {'text': f"[{channel}] {message}"}
        async with aiohttp.ClientSession() as session:
            async with session.post(self.webhook_url, json=payload) as resp:
                if resp.status >= 400:
                    raise RuntimeError(f"Slack error {resp.status}")
