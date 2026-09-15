from __future__ import annotations
import json
import logging
import os
import time
from typing import Any, Dict

try:
    from rq import Worker, Queue
    try:
        from rq import Connection
    except Exception:
        from rq.connections import Connection  # type: ignore
except Exception:
    Worker = None  # type: ignore
    Queue = None  # type: ignore
    Connection = None  # type: ignore
from redis import Redis
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

from src.core.storage.report_store import report_store
from src.core.redis_llm_queue import dequeue_task, dequeue_batch
from src.core.redis_helpers import publish_channel

logger = logging.getLogger(__name__)
_HEARTBEAT_KEY = 'janusec:worker:llm:heartbeat'


def _record_heartbeat(redis_url: str | None = None) -> None:
    try:
        url = redis_url or os.getenv('REDIS_URL')
        if not url:
            return
        client = Redis.from_url(url)
        client.set(_HEARTBEAT_KEY, str(time.time()), ex=30)
    except Exception:
        pass


def _process_single_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """Process a single LLM task and return result payload for publishing."""
    aid = task.get('assessment_id')
    task_id = task.get('task_id')
    with tracer.start_as_current_span('llm.process_task') as span:
        try:
            span.set_attribute('assessment_id', aid or 'unknown')
            span.set_attribute('task_id', task_id or 'unknown')
        except Exception:
            pass
        # pluggable provider: prefer cached_generate, else DEFAULT_CLIENT
        try:
            from src.reporting.llm_helper import cached_generate
            res = cached_generate(task.get('persona') or 'soc', task.get('payload') or {})
        except Exception:
            try:
                from src.integrations.llm_client import DEFAULT_CLIENT
                prompt = task.get('prompt') or json.dumps(task.get('payload') or {})
                gen = DEFAULT_CLIENT.generate(prompt)
                if isinstance(gen, dict) and 'text' in gen:
                    res = {'text': gen['text']}
                else:
                    res = {'text': str(gen)}
            except Exception:
                logger.exception('LLM provider unavailable')
                res = {'error': 'llm_unavailable'}

        # write result back into report_store under assessment id
        if aid:
            try:
                rep = report_store.get(aid) or {}
                if 'llm_results' not in rep:
                    rep['llm_results'] = {}
                rep['llm_results'][task_id] = {'result': res, 'ts': time.time()}
                rep.setdefault('llm_tasks_meta', {})[task_id] = {'processed_by': os.getenv('HOSTNAME') or 'worker', 'processed_ts': time.time()}
                report_store.save(aid, rep)
            except Exception:
                logger.exception('Failed saving llm result for %s', aid)
        return {'assessment_id': aid, 'task_id': task_id, 'result': res}


def run_worker(redis_url: str | None = None, queue_name: str = 'default') -> None:
    """Start an RQ worker that consumes jobs from a named queue.

    This run loop uses the RQ framework; for quick smoke runs you can call
    `python -m src.workers.llm_worker` which will start a worker.
    """
    redis_url = redis_url or os.getenv('REDIS_URL')
    conn = Redis.from_url(redis_url) if redis_url else Redis()
    _record_heartbeat(redis_url)
    if Worker is None or Queue is None or Connection is None:
        raise RuntimeError('rq_worker_unavailable')
    with Connection(conn):
        q = Queue(queue_name)
        w = Worker([q])
        logger.info('Starting RQ worker for queue=%s', queue_name)
        w.work(with_scheduler=False)


if __name__ == '__main__':
    # Simple loop that polls the global redis queue as a fallback if RQ isn't used.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--redis', help='Redis URL', default=os.getenv('REDIS_URL'))
    parser.add_argument('--use-rq', action='store_true', help='Use RQ worker loop instead of simple polling')
    args = parser.parse_args()
    if args.use_rq:
        run_worker(args.redis)
    else:
        logger.info('Starting simple polling worker (batch dequeue)')
        try:
            batch_size = int(os.getenv('LLM_BATCH_SIZE', '10'))
            while True:
                _record_heartbeat(args.redis)
                tasks = dequeue_batch(batch_size=batch_size, timeout=5)
                if not tasks:
                    continue
                # process tasks in a single batch and publish partial results
                try:
                    for idx in range(0, len(tasks), batch_size):
                        batch = tasks[idx: idx + batch_size]
                        # process and publish for each task
                        for t in batch:
                            out = _process_single_task(t)
                            aid = out.get('assessment_id')
                            try:
                                channel = f"assessment:events:{aid}"
                                publish_channel(channel, {
                                    'type': 'partial_result',
                                    'assessment_id': aid,
                                    'task_id': out.get('task_id'),
                                    'result': out.get('result'),
                                    'batches_done': 1,
                                    'total_batches_estimate': None,
                                    'last_updated_ts': time.time(),
                                })
                            except Exception:
                                logger.exception('Failed publishing partial result for %s', aid)
                except Exception:
                    logger.exception('Batch processing failed, continuing')
        except KeyboardInterrupt:
            logger.info('Worker exiting')
