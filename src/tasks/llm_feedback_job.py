from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


async def _llm_feedback_loop(app, interval: int) -> None:
    from src.api.runtime_state import get_server_runtime_state  # type: ignore
    from src.feedback.llm_feedback import export_dataset, summarize_feedback  # type: ignore
    from src.ml.retrain import enqueue_labels, run_retrain_once  # type: ignore

    while True:  # pragma: no cover - background loop
        metrics: Dict[str, Any] = {'last_run': time.time(), 'status': 'ok'}
        try:
            summary = summarize_feedback(limit=int(os.getenv('LLM_FEEDBACK_SUMMARY_LIMIT', '5000') or 5000))
            dataset_path = export_dataset(limit=int(os.getenv('LLM_FEEDBACK_EXPORT_LIMIT', '20000') or 20000))
            metrics['feedback_count'] = summary.get('count', 0)
            metrics['model_breakdown'] = summary.get('models', {})
            metrics['top_factors'] = summary.get('top_factors')
            metrics['dataset_path'] = dataset_path
            labels: List[Dict[str, Any]] = []
            if dataset_path:
                try:
                    with open(dataset_path, 'r', encoding='utf-8') as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            payload = entry.get('llm_payload') or entry.get('payload') or entry
                            disposition = (entry.get('disposition') or '').lower()
                            score = 0.5
                            if disposition in {'malicious', 'needs_review'}:
                                score = 1.0 if disposition == 'malicious' else 0.7
                            elif disposition == 'benign':
                                score = 0.0
                            labels.append({'payload': payload, 'score': score})
                except Exception as exc:
                    logger.debug('Unable to parse feedback dataset for retrain: %s', exc)
            if labels:
                enqueue_labels(labels)
            retrain_ran = run_retrain_once() if labels else False
            metrics['labels_used'] = len(labels)
            metrics['retrain_status'] = 'completed' if retrain_ran else ('skipped' if labels else 'no_labels')
        except Exception as exc:  # pragma: no cover - protective logging
            metrics['status'] = 'error'
            metrics['error'] = str(exc)
            logger.warning('LLM feedback job failed: %s', exc)
        finally:
            runtime = get_server_runtime_state(app)
            runtime.llm_feedback_metrics = metrics
        await asyncio.sleep(max(60, interval))


def register_llm_feedback_job(app) -> None:
    """Register nightly export/retrain loop."""
    try:
        interval = int(os.getenv('LLM_FEEDBACK_JOB_INTERVAL_SECONDS', '86400') or 86400)
    except Exception:
        interval = 86400
    if interval <= 0:
        logger.info('LLM feedback job disabled (interval=%s)', interval)
        return

    async def _starter():  # pragma: no cover
        await _llm_feedback_loop(app, interval)

    try:
        app.add_event_handler('startup', lambda: asyncio.create_task(_starter()))
        logger.info('Registered LLM feedback scheduler (interval=%s)', interval)
    except Exception as exc:
        logger.warning('Failed to register LLM feedback scheduler: %s', exc)
