import asyncio
import json
import logging
import os
import time
from typing import Dict, Any, List

import httpx
from src.repositories import audit_repo

logger = logging.getLogger(__name__)

# In-memory asyncio queue; started on app startup
_ASYNC_Q: asyncio.Queue | None = None
_CLIENT: httpx.AsyncClient | None = None


async def _delivery_worker(app, interval: int = 0):
    global _ASYNC_Q, _CLIENT
    if _ASYNC_Q is None:
        _ASYNC_Q = asyncio.Queue()
    if _CLIENT is None:
        _CLIENT = httpx.AsyncClient(timeout=15.0)
    while True:  # pragma: no cover - background loop
        try:
            task = await _ASYNC_Q.get()
            if task is None:
                break
            audit_id = task.get('audit_id')
            recipients: List[Dict[str, Any]] = task.get('recipients') or []
            body = task.get('body')
            results = []
            for r in recipients:
                url = r.get('url')
                headers = r.get('headers') or {}
                try:
                    if isinstance(body, dict):
                        resp = await _CLIENT.post(url, json=body, headers=headers)
                    else:
                        resp = await _CLIENT.post(url, content=str(body).encode('utf-8'), headers=headers)
                    results.append({'url': url, 'status_code': getattr(resp, 'status_code', None), 'ok': resp.status_code >= 200 and resp.status_code < 300})
                except Exception as exc:
                    results.append({'url': url, 'error': str(exc)})
            try:
                audit_repo.update_audit_status(audit_id, 'sent', {'results': results, 'ts': int(time.time())})
            except Exception:
                pass
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception('Delivery worker error')
        finally:
            await asyncio.sleep(0 if interval <= 0 else interval)


def register_delivery_worker(app, interval: int = 0) -> None:
    global _ASYNC_Q
    try:
        if _ASYNC_Q is None:
            _ASYNC_Q = asyncio.Queue()
        app.add_event_handler('startup', lambda: asyncio.create_task(_delivery_worker(app, interval)))
        logger.info('Registered delivery async worker (interval=%s)', interval)
    except Exception:
        logger.exception('Failed to register delivery worker')


def enqueue_delivery(audit_record: Dict[str, Any], recipients: List[Dict[str, Any]], body: Any) -> int:
    """Insert audit and enqueue a delivery task into the asyncio queue. Returns audit_id."""
    global _ASYNC_Q
    try:
        aid = audit_repo.insert_audit(audit_record)
    except Exception:
        aid = None
    task = {'audit_id': aid, 'recipients': recipients, 'body': body}
    # Put into queue if running under event loop; else write a small fallback to file
    try:
        if _ASYNC_Q is not None:
            # non-blocking put via loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(lambda: _ASYNC_Q.put_nowait(task))
            else:
                # running in sync test harness; put directly
                loop.run_until_complete(_ASYNC_Q.put(task))
        else:
            # fallback: write a jsonl file consumed by feedback batcher or admin tool
            path = os.getenv('OUTBOX_BATCH_PATH', 'data/outbox_batch.jsonl')
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(task) + '\n')
    except Exception:
        pass
    return aid


async def shutdown_delivery_worker():
    global _ASYNC_Q, _CLIENT
    try:
        if _ASYNC_Q is not None:
            await _ASYNC_Q.put(None)
        if _CLIENT is not None:
            await _CLIENT.aclose()
    except Exception:
        pass
