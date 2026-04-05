from __future__ import annotations
import asyncio, time, logging
from typing import Dict, Any
logger = logging.getLogger(__name__)

try:
    from src.api.runtime_state import EVENT_QUEUE
except Exception:
    EVENT_QUEUE = None

from .playbook_executor import PlaybookExecutor, PlayStep

_executor = PlaybookExecutor()

async def dispatch_playbook(playbook: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    exec_id = playbook.get('id') or f"exec-{int(time.time()*1000)}"
    steps_raw = playbook.get('steps', [])
    # normalize to PlayStep-like dicts
    steps = []
    for i, s in enumerate(steps_raw):
        sid = s.get('id') or f"s{i}"
        steps.append({'id': sid, 'action': s.get('action'), 'params': s.get('params', {}), 'depends_on': s.get('depends_on', [])})
    record = {'exec_id': exec_id, 'playbook': playbook, 'steps': steps, 'context': context}
    # Try to enqueue to EVENT_QUEUE if available
    try:
        if EVENT_QUEUE is not None and hasattr(EVENT_QUEUE, 'enqueue'):
            await EVENT_QUEUE.enqueue({'type': 'playbook_execution', 'payload': record})
            return {'status': 'queued', 'exec_id': exec_id}
    except Exception:
        logger.debug('EVENT_QUEUE enqueue failed, falling back to local execution')
    # Local execution: translate steps into PlayStep dataclass for PlaybookExecutor
    psteps = []
    for s in steps:
        ps = PlayStep(id=s['id'], action=s.get('action','unknown'), params=s.get('params', {}), depends_on=s.get('depends_on', []))
        psteps.append(ps)
    # Run executor in background
    async def _run():
        try:
            await _executor.execute(exec_id, psteps, context)
        except Exception as e:
            logger.exception('playbook execute error: %s', e)
    try:
        asyncio.create_task(_run())
        return {'status': 'started', 'exec_id': exec_id}
    except Exception:
        # synchronous fallback
        res = await _executor.execute(exec_id, psteps, context)
        return {'status': 'completed', 'exec_id': exec_id, 'result': res}

__all__ = ['dispatch_playbook']
