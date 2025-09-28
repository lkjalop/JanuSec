from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

from adapters.eclipse_xdr import EclipseXDRConnector
from analytics.drift_analyzer import drift_loop
from core.config_manager import ConfigManager
from core.decision_engine import DecisionEngine
from core.event_pipeline import EventPipeline
from core.metrics_collector import MetricsCollector
from core.module_registry import ModuleRegistry
from maintenance.vector_index_maintainer import maintenance_loop as vector_index_maintenance_loop
from modules.adaptive_tuner import AdaptiveTuner
from repositories import audit_repo, feedback_repo  # noqa: F401 - retained for side effects/tests
from db import database as db

from .background import BackgroundTaskMixin
from .persistence import DecisionPersistenceMixin
from .routing import RoutingMixin
from .types import ProcessingResult


class SecurityOrchestrator(DecisionPersistenceMixin, RoutingMixin, BackgroundTaskMixin):
    """Main orchestration engine coordinating ingestion, analysis, and response."""

    def __init__(self, config_path: str = 'config/main.yaml') -> None:
        self.config = ConfigManager(config_path)
        self.module_registry = ModuleRegistry(self.config)
        self.event_pipeline = EventPipeline(self.config)
        self.decision_engine = DecisionEngine(self.config)
        self.metrics = MetricsCollector(self.config)
        self.adaptive_tuner = AdaptiveTuner(self.config)
        self.xdr_connector = EclipseXDRConnector(self.config)

        self.factor_weights: dict[str, float] = {}
        self.slack_notifier = None
        self.events_processed = 0
        self.start_time = time.time()
        self.health_status = 'starting'
        self.logger = logging.getLogger(__name__)

        self._ensure_background_tasks()
        self._maintenance_stop: Optional[asyncio.Event] = None
        self._drift_stop: Optional[asyncio.Event] = None

        try:
            self.event_pipeline.config.module_registry = self.module_registry
        except Exception:
            pass

    async def initialize(self) -> None:
        self.logger.info('Initializing Security Orchestrator...')
        try:
            await self._init_database()
            await self.module_registry.initialize()
            await self.event_pipeline.initialize()
            await self.decision_engine.initialize()
            await self.metrics.initialize()
            await self.adaptive_tuner.initialize()
            await self._run_optional_diagnostics()
            await self.xdr_connector.initialize()
            await self._configure_slack()
            self._start_background_loops()
            self.health_status = 'healthy'
            self.logger.info('Security Orchestrator initialized successfully')
        except Exception:
            self.health_status = 'failed'
            self.logger.exception('Failed to initialize orchestrator')
            raise

    async def _init_database(self) -> None:
        try:
            await db.init_pool()
        except Exception as exc:
            self.logger.warning('Database initialization skipped: %s', exc)

    async def _run_optional_diagnostics(self) -> None:
        try:
            from modules import adaptive_tuner as _adaptive_tuner  # type: ignore
            sklearn_flag = getattr(_adaptive_tuner, '_SKLEARN_AVAILABLE', False)
            scipy_flag = getattr(_adaptive_tuner, '_SCIPY_AVAILABLE', False)
            from modules import baseline as _baseline  # type: ignore
            bloom_impl = getattr(_baseline.BloomFilter, '__module__', 'unknown')
            degraded: list[str] = []
            if not sklearn_flag:
                degraded.append('scikit-learn')
            if not scipy_flag:
                degraded.append('scipy')
            if 'pybloom_live' not in bloom_impl:
                degraded.append('pybloom-live (using set fallback)')
            if degraded:
                self.logger.warning('Optional components degraded: %s', ', '.join(degraded))
            else:
                self.logger.info('All optional ML / bloom dependencies present')
        except Exception as exc:
            self.logger.debug('Diagnostics check skipped: %s', exc)

    async def _configure_slack(self) -> None:
        try:
            slack_cfg = self.config.get('slack') if hasattr(self.config, 'get') else None
            if not slack_cfg or not getattr(slack_cfg, 'enabled', False):
                return
            channel_map = {}
            if getattr(slack_cfg, 'channel_map', None):
                channel_map = {k: v for k, v in slack_cfg.channel_map.model_dump().items() if v}
            from integrations.slack_notifier import SlackNotifier
            self.slack_notifier = SlackNotifier(
                webhook_url=slack_cfg.webhook_url,
                default_channel=slack_cfg.default_channel,
                channel_map=channel_map,
                rate_limit_per_minute=slack_cfg.rate_limit_per_minute,
            )
            self.logger.info('Slack notifier enabled')
        except Exception as exc:
            self.logger.warning('Slack notifier init failed: %s', exc)

    def _start_background_loops(self) -> None:
        self._spawn_task(self.health_monitor(), 'health_monitor')
        self._spawn_task(self.adaptive_tuning_loop(), 'adaptive_tuning_loop')
        self._spawn_task(self.metrics_collection_loop(), 'metrics_collection')
        self._spawn_task(self.feedback_weight_loop(), 'feedback_weight_loop')

        if self._maintenance_stop is None:
            self._maintenance_stop = asyncio.Event()
        try:
            self._spawn_task(vector_index_maintenance_loop(self._maintenance_stop), 'vector_index_maintenance')
        except Exception:
            pass

        if self._drift_stop is None:
            self._drift_stop = asyncio.Event()
        try:
            self._spawn_task(drift_loop(self.metrics, self._drift_stop), 'drift_monitor')
        except Exception:
            pass

    def apply_factor_weights(self, weights: Dict[str, float], source: str = 'api') -> None:
        if not isinstance(weights, dict):
            raise ValueError('weights must be dict')
        self.factor_weights = {str(k): float(v) for k, v in weights.items() if isinstance(v, (int, float))}
        self.logger.info('Applied %d factor weights (source=%s)', len(self.factor_weights), source)

    async def shutdown(self) -> None:
        self.logger.info('Starting graceful shutdown...')
        self.health_status = 'shutting_down'
        if self._maintenance_stop:
            self._maintenance_stop.set()
        if self._drift_stop:
            self._drift_stop.set()
        await self.module_registry.shutdown()
        await self.event_pipeline.shutdown()
        await self.decision_engine.shutdown()
        await self.adaptive_tuner.shutdown()
        await self.xdr_connector.shutdown()
        await self.metrics.flush_and_shutdown()
        await self.cancel_background_tasks()
        self.logger.info('Shutdown complete')


__all__ = ['SecurityOrchestrator', 'ProcessingResult']
