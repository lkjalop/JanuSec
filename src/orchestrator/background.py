from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Awaitable

from repositories import factor_weights_repo


class BackgroundTaskMixin:
    module_registry: Any
    metrics: Any
    adaptive_tuner: Any
    decision_engine: Any
    logger: Any
    events_processed: int
    start_time: float
    health_status: str
    factor_weights: dict[str, float]

    def _ensure_background_tasks(self) -> None:
        if not hasattr(self, '_bg_tasks'):
            self._bg_tasks: list[asyncio.Task] = []

    def _spawn_task(self, coro: Awaitable[Any], name: str) -> asyncio.Task:
        self._ensure_background_tasks()
        task = asyncio.create_task(coro, name=name)
        self._bg_tasks.append(task)
        return task

    async def health_monitor(self) -> None:
        fast_mode = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'}
        base_interval = float(os.getenv('HEALTH_LOOP_INTERVAL', '30'))
        interval = 0.1 if fast_mode else base_interval
        while True:
            try:
                health_status = await self.module_registry.health_check()
                if not health_status['healthy']:
                    self.logger.warning("Unhealthy modules detected: %s", health_status['unhealthy'])
                    self.health_status = 'degraded'
                else:
                    self.health_status = 'healthy'
                await self.metrics.record_health_status(self.health_status)
                await asyncio.sleep(interval)
            except Exception as exc:
                self.logger.error("Health monitor error: %s", exc)
                await asyncio.sleep(60)

    async def adaptive_tuning_loop(self) -> None:
        fast_mode = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'}
        base_interval = float(os.getenv('TUNING_LOOP_INTERVAL', '3600'))
        interval = 0.1 if fast_mode else base_interval
        while True:
            try:
                await asyncio.sleep(interval)
                tuning_results = await self.adaptive_tuner.run_tuning_cycle()
                if tuning_results.has_recommendations:
                    self.logger.info("Adaptive tuning recommendations: %s", tuning_results.summary)
                    await self._apply_tuning_recommendations(tuning_results)
            except Exception as exc:
                self.logger.error("Adaptive tuning error: %s", exc)

    async def metrics_collection_loop(self) -> None:
        fast_mode = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'}
        base_interval = float(os.getenv('METRICS_LOOP_INTERVAL', '60'))
        interval = 0.1 if fast_mode else base_interval
        while True:
            try:
                await asyncio.sleep(interval)
                system_metrics = {
                    'events_processed_total': self.events_processed,
                    'uptime_seconds': time.time() - self.start_time,
                    'health_status': self.health_status,
                }
                await self.metrics.record_system_metrics(system_metrics)
                await self._record_embedding_stats()
            except Exception as exc:
                self.logger.error("Metrics collection error: %s", exc)

    async def feedback_weight_loop(self) -> None:
        smoothing = 5
        scale = 0.1
        fast_mode = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'}
        base_interval = float(os.getenv('FEEDBACK_LOOP_INTERVAL', '300'))
        interval = 0.1 if fast_mode else base_interval
        while True:
            try:
                from db.database import get_pool
                pool = await get_pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT factor,
                               sum(CASE WHEN vote=1 THEN 1 ELSE 0 END) AS up,
                               sum(CASE WHEN vote=-1 THEN 1 ELSE 0 END) AS down
                        FROM factor_feedback
                        GROUP BY factor
                        LIMIT 1000
                        """
                    )
                    new_weights: dict[str, float] = {}
                    for row in rows:
                        up = row['up'] or 0
                        down = row['down'] or 0
                        total = up + down
                        if total == 0:
                            continue
                        weight = ((up - down) / (total + smoothing)) * scale
                        weight = max(-0.25, min(0.25, weight))
                        factor = row['factor']
                        new_weights[factor] = weight
                        try:
                            await factor_weights_repo.upsert_factor_weight(factor, weight)
                        except Exception:
                            pass
                    self.factor_weights = new_weights
            except Exception as exc:
                self.logger.debug('Feedback weight aggregation skipped: %s', exc)
            await asyncio.sleep(interval)

    async def _record_embedding_stats(self) -> None:
        try:
            from db.database import get_pool
            pool = await get_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch('SELECT embedding_json FROM factor_embeddings ORDER BY id DESC LIMIT 200')
                norms = []
                for row in rows:
                    emb = row.get('embedding_json')
                    if isinstance(emb, list) and emb:
                        norm = sum(x * x for x in emb) ** 0.5
                        norms.append(norm)
                if norms:
                    avg_norm = sum(norms) / len(norms)
                    await self.metrics.record_embedding_stats(avg_norm)
        except Exception:
            pass

    async def _apply_tuning_recommendations(self, recommendations) -> None:
        for rec in recommendations.changes:
            if rec.confidence > 0.8 and rec.risk_level == 'low':
                await self._apply_recommendation(rec)
            else:
                await self.adaptive_tuner.queue_for_approval(rec)

    async def _apply_recommendation(self, recommendation) -> None:
        if recommendation.type == 'threshold_adjustment':
            await self.decision_engine.update_thresholds(recommendation.parameters)
        elif recommendation.type == 'pattern_optimization':
            regex_module = await self.module_registry.get_module('regex_engine')
            await regex_module.update_patterns(recommendation.parameters)

    async def cancel_background_tasks(self) -> None:
        self._ensure_background_tasks()
        for task in self._bg_tasks:
            task.cancel()
        for task in list(self._bg_tasks):
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.logger.debug('Background task %s raised %s', getattr(task, 'get_name', lambda: 'task')(), exc)
        self._bg_tasks.clear()
