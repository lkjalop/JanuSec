from __future__ import annotations

import asyncio
import json
import os
import time
import hashlib
import random
from typing import Any
try:
    from prometheus_client import Counter
except Exception:
    Counter = None
try:
    from prometheus_client import Gauge
except Exception:
    Gauge = None
try:
    from src.api.metrics_init import ensure_metrics, _safe_counter, _safe_gauge  # type: ignore
except Exception:
    ensure_metrics = None
    _safe_counter = None
    _safe_gauge = None
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class InFlightTracker:
    """Simple in-memory tracker for qids with TTL cleanup."""
    def __init__(self, ttl_seconds: int = 300):
        self._map: dict[str, float] = {}
        self._ttl = ttl_seconds

    def add(self, qid: str):
        self._map[qid] = time.time()

    def discard(self, qid: str):
        self._map.pop(qid, None)

    def contains(self, qid: str) -> bool:
        ts = self._map.get(qid)
        if ts is None:
            return False
        if time.time() - ts > self._ttl:
            # expired
            self._map.pop(qid, None)
            return False
        return True

    def prune(self):
        now = time.time()
        remove = [k for k, v in self._map.items() if now - v > self._ttl]
        for k in remove:
            self._map.pop(k, None)

    def count(self) -> int:
        self.prune()
        return len(self._map)


try:
    from incident.persistence import upsert_incident  # type: ignore
except Exception:
    from src.incident.persistence import upsert_incident  # type: ignore

OUTBOX_PATH = os.getenv('OUTBOX_PATH', 'data/outbox.jsonl')
OUTBOX_STATE = os.getenv('OUTBOX_STATE_PATH', 'data/outbox_state.json')
DLQ_PATH = os.getenv('OUTBOX_DLQ_PATH', 'data/outbox_dlq.jsonl')
DLQ_MAX_LINES = int(os.getenv('OUTBOX_DLQ_MAX_LINES', '1000') or 1000)
POLL_MS = int(os.getenv('OUTBOX_POLL_INTERVAL_MS', '750'))
WORKERS = int(os.getenv('OUTBOX_WORKERS', '2'))
MAX_RETRIES = int(os.getenv('OUTBOX_MAX_RETRIES', '5'))
CB_WINDOW = int(os.getenv('OUTBOX_CB_WINDOW', '50'))
CB_FAIL_RATIO = float(os.getenv('OUTBOX_CB_FAIL_RATIO', '0.6'))
CB_COOLDOWN = int(os.getenv('OUTBOX_CB_COOLDOWN_SEC', '60'))


def _load_state():
    try:
        if os.path.exists(OUTBOX_STATE):
            with open(OUTBOX_STATE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {'offset': 0, 'circuit_open_until': 0, 'recent_failures': []}


def _save_state(s):
    os.makedirs(os.path.dirname(OUTBOX_STATE) or '.', exist_ok=True)
    with open(OUTBOX_STATE, 'w', encoding='utf-8') as f:
        json.dump(s, f)


async def _tail_file(queue: asyncio.Queue, stop_event: asyncio.Event, in_flight: InFlightTracker, inflight_gauge=None, qlen_gauge=None, oldest_age_gauge=None):
    state = _load_state()
    offset = state.get('offset', 0)
    while not stop_event.is_set():
        try:
            # circuit breaker: pause tailing if circuit open
            now = time.time()
            if state.get('circuit_open_until',0) > now:
                logger.warning('tailer circuit breaker open until %s', state['circuit_open_until'])
                await asyncio.sleep(min(POLL_MS/1000, state['circuit_open_until'] - now))
                continue
            if not os.path.exists(OUTBOX_PATH):
                await asyncio.sleep(POLL_MS/1000)
                continue
            try:
                fsize = os.path.getsize(OUTBOX_PATH)
            except Exception:
                fsize = None
            logger.info('tailer state offset=%s outbox_size=%s', offset, fsize)
            with open(OUTBOX_PATH, 'r', encoding='utf-8') as f:
                f.seek(offset)
                oldest_ts = None
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        # Try to extract event timestamp for oldest age metric
                        ts = ev.get('ts') or ev.get('timestamp') or None
                        if ts is not None:
                            try:
                                ts = float(ts)
                                if oldest_ts is None or ts < oldest_ts:
                                    oldest_ts = ts
                            except Exception:
                                pass
                    except Exception as e:
                        logger.error('tailer: corrupt outbox entry, writing to DLQ: %s', line)
                        _dlq_write({'raw': line}, f'corrupt: {e}', 0)
                        continue
                    qid = hashlib.sha256(json.dumps(ev, sort_keys=True).encode('utf-8')).hexdigest()[:8]
                    if in_flight.contains(qid):
                        logger.info('tailer skipping already in-flight qid=%s', qid)
                    else:
                        # persist offset before enqueueing to avoid race with worker failure
                        offset = f.tell()
                        state['offset'] = offset
                        _save_state(state)
                        in_flight.add(qid)
                        if inflight_gauge is not None:
                            try:
                                inflight_gauge.set(in_flight.count())
                            except Exception:
                                pass
                        if qlen_gauge is not None:
                            try:
                                qlen_gauge.set(queue.qsize())
                            except Exception:
                                pass
                        logger.info('tailer enqueue qid=%s event=%s offset=%s', qid, ev, offset)
                        await queue.put({'event': ev, 'attempts': 0, 'qid': qid})
                    try:
                        if OUTBOX_EVENTS is not None:
                            OUTBOX_EVENTS.inc()
                    except Exception:
                        pass
                logger.info('tailer updated offset=%s', f.tell())
                if oldest_age_gauge is not None and oldest_ts is not None:
                    try:
                        oldest_age_gauge.set(max(0, time.time() - oldest_ts))
                    except Exception:
                        pass
            state['offset'] = offset
            _save_state(state)
        except Exception as e:
            logger.exception('tailer exception: %s', e)
            await asyncio.sleep(1)
        await asyncio.sleep(POLL_MS/1000)


def _register_failure():
    state = _load_state()
    recent = state.get('recent_failures', [])
    recent.append(time.time())
    # prune to window size
    if len(recent) > CB_WINDOW:
        recent = recent[-CB_WINDOW:]
    state['recent_failures'] = recent
    # compute failure ratio
    total = len(recent)
    if total >= 1:
        # failure ratio = failures / window (approx)
        ratio = len(recent) / CB_WINDOW
        if ratio >= CB_FAIL_RATIO:
            state['circuit_open_until'] = int(time.time() + CB_COOLDOWN)
    _save_state(state)
    logger.info('registered failure, recent count=%d, circuit_open_until=%s', len(recent), state.get('circuit_open_until'))


async def _worker(name: str, queue: asyncio.Queue, stop_event: asyncio.Event, in_flight: InFlightTracker, inflight_gauge=None):
    while not stop_event.is_set():
        try:
            item = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        ev = item.get('event')
        attempts = item.get('attempts', 0)
        qid = item.get('qid')
        logger.info('worker %s got queue item qid=%s attempts=%s event=%s', name, qid, attempts, ev)
        try:
            # process: upsert_incident should be idempotent
            await maybe_await(upsert_incident(ev))
            # success: remove from in-flight
            try:
                in_flight.discard(qid)
                if inflight_gauge is not None:
                    try:
                        inflight_gauge.set(in_flight.count())
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception as e:
            logger.exception('worker %s processing failed attempt=%s err=%s', name, attempts, e)
            attempts += 1
            if OUTBOX_FAILED is not None:
                try:
                    OUTBOX_FAILED.inc()
                except Exception:
                    pass
            _register_failure()
            if attempts >= MAX_RETRIES:
                # push to DLQ
                logger.info('attempts (%s) >= MAX_RETRIES (%s), sending to DLQ qid=%s event=%s', attempts, MAX_RETRIES, qid, ev)
                _dlq_write(ev, str(e), attempts)
                try:
                    in_flight.discard(qid)
                    if inflight_gauge is not None:
                        try:
                            inflight_gauge.set(in_flight.count())
                        except Exception:
                            pass
                except Exception:
                    pass
            else:
                # backoff and requeue
                backoff = min(30, (2 ** attempts) + random.random())
                await asyncio.sleep(backoff)
                logger.info('requeueing qid=%s event=%s attempts=%s backoff=%s', qid, ev, attempts, backoff)
                await queue.put({'event': ev, 'attempts': attempts, 'qid': qid})
        finally:
            try:
                queue.task_done()
            except Exception:
                pass
        try:
            if OUTBOX_PROCESSED is not None:
                OUTBOX_PROCESSED.inc()
        except Exception:
            pass



def _dlq_write(ev: Any, err: str, attempts: int, error_type: str | None = None, source: str | None = None):
    os.makedirs(os.path.dirname(DLQ_PATH) or '.', exist_ok=True)
    rec = {
        'ts': time.time(),
        'error': err,
        'error_type': error_type or 'unknown',
        'attempts': attempts,
        'source': source or 'outbox',
        'event': ev
    }
    # rotate DLQ by max lines if configured
    try:
        if DLQ_MAX_LINES and os.path.exists(DLQ_PATH):
            with open(DLQ_PATH, 'r', encoding='utf-8') as rf:
                lines = rf.readlines()
            if len(lines) >= DLQ_MAX_LINES:
                start = max(0, len(lines) - (DLQ_MAX_LINES - 1))
                with open(DLQ_PATH, 'w', encoding='utf-8') as wf:
                    wf.writelines(lines[start:])
    except Exception:
        pass
    try:
        with open(DLQ_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec) + '\n')
        logger.debug('wrote DLQ record to %s: %s', DLQ_PATH, rec)
    except Exception:
        logger.exception('failed to write DLQ record')
    try:
        if OUTBOX_DLQ is not None:
            OUTBOX_DLQ.inc()
    except Exception:
        pass


# Prometheus metrics (prefer project-safe registration helpers)
try:
    if ensure_metrics is not None:
        try:
            ensure_metrics()
        except Exception:
            pass
        OUTBOX_EVENTS = _safe_counter('outbox_events_total', 'Total events read from outbox') if _safe_counter else None
        OUTBOX_PROCESSED = _safe_counter('outbox_events_processed_total', 'Total events processed') if _safe_counter else None
        OUTBOX_FAILED = _safe_counter('outbox_events_failed_total', 'Total events failed') if _safe_counter else None
        OUTBOX_DLQ = _safe_counter('outbox_events_dlq_total', 'Total events sent to DLQ') if _safe_counter else None
        OUTBOX_INFLIGHT = _safe_gauge('outbox_inflight_gauge', 'Number of in-flight outbox events') if _safe_gauge else None
        OUTBOX_QUEUE_LEN = _safe_gauge('outbox_queue_length', 'Current outbox queue length') if _safe_gauge else None
        OUTBOX_OLDEST_AGE = _safe_gauge('outbox_oldest_event_age', 'Age in seconds of oldest event in outbox') if _safe_gauge else None
    else:
        try:
            from prometheus_client import Counter as _C, Gauge as _G
            OUTBOX_EVENTS = _C('outbox_events_total', 'Total events read from outbox')
            OUTBOX_PROCESSED = _C('outbox_events_processed_total', 'Total events processed')
            OUTBOX_FAILED = _C('outbox_events_failed_total', 'Total events failed')
            OUTBOX_DLQ = _C('outbox_events_dlq_total', 'Total events sent to DLQ')
            OUTBOX_INFLIGHT = _G('outbox_inflight_gauge', 'Number of in-flight outbox events')
            OUTBOX_QUEUE_LEN = _G('outbox_queue_length', 'Current outbox queue length')
            OUTBOX_OLDEST_AGE = _G('outbox_oldest_event_age', 'Age in seconds of oldest event in outbox')
        except Exception:
            OUTBOX_EVENTS = OUTBOX_PROCESSED = OUTBOX_FAILED = OUTBOX_DLQ = None
            OUTBOX_INFLIGHT = OUTBOX_QUEUE_LEN = OUTBOX_OLDEST_AGE = None
except Exception:
    OUTBOX_EVENTS = OUTBOX_PROCESSED = OUTBOX_FAILED = OUTBOX_DLQ = None
    OUTBOX_INFLIGHT = OUTBOX_QUEUE_LEN = OUTBOX_OLDEST_AGE = None


async def maybe_await(v):
    if asyncio.iscoroutine(v):
        return await v
    return v


async def run_outbox(stop_event: asyncio.Event):
    queue: asyncio.Queue = asyncio.Queue()
    in_flight = InFlightTracker(ttl_seconds=300)
    inflight_gauge = OUTBOX_INFLIGHT
    qlen_gauge = OUTBOX_QUEUE_LEN
    oldest_age_gauge = OUTBOX_OLDEST_AGE
    tailer = asyncio.create_task(_tail_file(queue, stop_event, in_flight, inflight_gauge, qlen_gauge, oldest_age_gauge))
    workers = [asyncio.create_task(_worker(f'worker-{i}', queue, stop_event, in_flight, inflight_gauge)) for i in range(WORKERS)]
    try:
        await stop_event.wait()
    finally:
        tailer.cancel()
        for w in workers:
            w.cancel()
        # attempt graceful drain
        try:
            await asyncio.wait_for(queue.join(), timeout=5.0)
        except Exception:
            pass