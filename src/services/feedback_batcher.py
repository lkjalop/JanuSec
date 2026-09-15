import asyncio
import json
import logging
import os
import time
from typing import Dict, Any

from src.core.quality.factor_quality import get_quality_manager

logger = logging.getLogger(__name__)
FEEDBACK_BATCH_PATH = os.getenv('FEEDBACK_BATCH_PATH', 'data/feedback_batch.jsonl')


def append_feedback_to_batch(entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(FEEDBACK_BATCH_PATH) or '.', exist_ok=True)
    try:
        with open(FEEDBACK_BATCH_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        logger.debug('failed to append feedback to batch', exc_info=True)


async def _batch_loop(app, interval: int):
    while True:  # pragma: no cover - background loop
        try:
            if not os.path.exists(FEEDBACK_BATCH_PATH):
                await asyncio.sleep(max(5, interval))
                continue
            # read and rotate
            tmp = FEEDBACK_BATCH_PATH + f'.{int(time.time())}.processing'
            try:
                os.rename(FEEDBACK_BATCH_PATH, tmp)
            except Exception:
                await asyncio.sleep(max(5, interval))
                continue
            entries = []
            try:
                with open(tmp, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            continue
            except Exception:
                entries = []

            if entries:
                manager = get_quality_manager()
                # aggregate observations into a dict of {factor: {tp: N, fp: M}}
                obs = {}
                for e in entries:
                    f = e.get('factor') or e.get('correction_type')
                    if not f:
                        continue
                    rec = obs.setdefault(f, {'tp': 0, 'fp': 0})
                    t = e.get('correction_type')
                    if t == 'false_positive' or e.get('correction_type') == 'factor_disagreement':
                        rec['fp'] += 1
                    else:
                        # treat other corrections as tp for now
                        rec['tp'] += 1
                # apply observations
                try:
                    manager.apply_admin_observations(obs)
                    manager.persist(force=True)
                    # record telemetry snapshot into runtime state if needed
                    # emit optional admin metrics by storing to disk (existing load/save helpers will pick up)
                except Exception:
                    logger.exception('Failed to apply batch feedback')

            # cleanup processed file
            try:
                os.unlink(tmp)
            except Exception:
                pass
        except Exception:
            logger.exception('feedback batch loop error')
        await asyncio.sleep(max(60, interval))


def register_feedback_batcher(app) -> None:
    try:
        interval = int(os.getenv('FEEDBACK_BATCH_INTERVAL_SECONDS', '300') or 300)
    except Exception:
        interval = 300
    if interval <= 0:
        logger.info('Feedback batcher disabled (interval=%s)', interval)
        return

    async def _starter():
        await _batch_loop(app, interval)

    try:
        app.add_event_handler('startup', lambda: asyncio.create_task(_starter()))
        logger.info('Registered feedback batcher (interval=%s)', interval)
    except Exception as exc:
        logger.warning('Failed to register feedback batcher: %s', exc)
