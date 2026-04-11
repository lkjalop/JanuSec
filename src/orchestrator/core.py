from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional

from adapters.eclipse_xdr import EclipseXDRConnector
from analytics.drift_analyzer import drift_loop
from core.config_manager import ConfigManager
from core.decision_engine import DecisionEngine
from core.event_pipeline import EventPipeline
from core.metrics_collector import MetricsCollector
from core.module_registry import ModuleRegistry
from db import database as db
from maintenance.redis_temporal_maintainer import maintenance_loop as redis_temporal_maintenance_loop
from maintenance.vector_index_maintainer import maintenance_loop as vector_index_maintenance_loop
from modules.adaptive_tuner import AdaptiveTuner
from repositories import audit_repo, feedback_repo  # noqa: F401 - retained for side effects/tests

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
        self._maintenance_stop: asyncio.Event | None = None
        self._drift_stop: asyncio.Event | None = None
        self._email_ingest_stop: asyncio.Event | None = None

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

        # Optional Redis temporal cache maintenance (removes stale host entries)
        try:
            if os.getenv('REDIS_URL'):
                self._spawn_task(redis_temporal_maintenance_loop(self._maintenance_stop, __import__('core.correlation.redis_cache', fromlist=['build_cache']).build_cache), 'redis_temporal_maintenance')
        except Exception:
            pass

        # Start HopGraph pruning loop if hopgraph backend is configured
        try:
            # GLOBAL_HOPGRAPH may be attached to module_registry or global namespace
            gh = getattr(self, 'GLOBAL_HOPGRAPH', None) or globals().get('GLOBAL_HOPGRAPH')
            if gh and getattr(gh, 'backend', None):
                try:
                    self._spawn_task(self.prune_hopgraph_periodic(), 'prune_hopgraph_periodic')
                except Exception:
                    pass
        except Exception:
            pass

        if self._drift_stop is None:
            self._drift_stop = asyncio.Event()
        try:
            self._spawn_task(drift_loop(self.metrics, self._drift_stop), 'drift_monitor')
        except Exception:
            pass

        # Optional email ingestion loop (O365/Gmail) gated by env
        try:
            if os.getenv('EMAIL_INGEST_ENABLED') in ('1', 'true', 'yes'):
                if self._email_ingest_stop is None:
                    self._email_ingest_stop = asyncio.Event()
                self._spawn_task(self.email_ingest_loop(self._email_ingest_stop), 'email_ingest_loop')
        except Exception:
            pass

    def apply_factor_weights(self, weights: dict[str, float], source: str = 'api') -> None:
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
        if self._email_ingest_stop:
            self._email_ingest_stop.set()
        await self.module_registry.shutdown()
        await self.event_pipeline.shutdown()
        await self.decision_engine.shutdown()
        await self.adaptive_tuner.shutdown()
        await self.xdr_connector.shutdown()
        await self.metrics.flush_and_shutdown()
        await self.cancel_background_tasks()
        self.logger.info('Shutdown complete')

    async def email_ingest_loop(self, stop_evt: asyncio.Event) -> None:
        """Background loop polling email providers and routing to pipeline.

        Uses existing lightweight collectors for O365/Gmail. Keeps minimal
        state for since_ts, normalizes events, and calls process_event.
        """
        self.logger.info('Email ingest loop starting')
        try:
            from src.collectors.email_o365_adapter import O365EmailCollector  # type: ignore
        except Exception:
            O365EmailCollector = None  # type: ignore
        try:
            from src.collectors.email_gmail_adapter import GmailEmailCollector  # type: ignore
        except Exception:
            GmailEmailCollector = None  # type: ignore
        try:
            from src.pipeline.normalizer import normalize_o365_event, normalize_gmail_event  # type: ignore
        except Exception:
            normalize_o365_event = None  # type: ignore
            normalize_gmail_event = None  # type: ignore

        o365 = O365EmailCollector() if O365EmailCollector else None
        gmail = GmailEmailCollector() if GmailEmailCollector else None
        since_o365 = time.time() - 3600
        since_gmail = time.time() - 3600

        poll_interval = float(os.getenv('EMAIL_INGEST_INTERVAL_SEC', '30') or 30)
        batch_sleep = float(os.getenv('EMAIL_INGEST_BATCH_SLEEP_MS', '50') or 50) / 1000.0

        while not stop_evt.is_set():
            try:
                events: list[dict[str, Any]] = []
                now_ts = time.time()
                if o365:
                    try:
                        raw_list = o365.fetch_events(since_o365)
                        since_o365 = now_ts
                        for raw in raw_list or []:
                            if normalize_o365_event:
                                ev_n = normalize_o365_event(raw)
                            else:
                                ev_n = {'event_id': raw.get('id') or f"o365-{int(now_ts*1000)}", 'ts': now_ts, 'domain': 'email', 'ingest_source': 'o365', 'raw': raw, 'factors': []}
                            events.append(self._compose_email_event(ev_n, 'o365_message'))
                        try:
                            await self.metrics.record_email_poll_success(len(raw_list or []))
                        except Exception:
                            pass
                    except Exception as exc:
                        self.logger.debug('O365 email polling error: %s', exc)
                        try:
                            await self.metrics.record_email_poll_error(1)
                        except Exception:
                            pass
                if gmail:
                    try:
                        raw_list = gmail.fetch_events(since_gmail)
                        since_gmail = now_ts
                        for raw in raw_list or []:
                            if normalize_gmail_event:
                                ev_n = normalize_gmail_event(raw)
                            else:
                                ev_n = {'event_id': raw.get('id') or f"gmail-{int(now_ts*1000)}", 'ts': now_ts, 'domain': 'email', 'ingest_source': 'gmail', 'raw': raw, 'factors': []}
                            events.append(self._compose_email_event(ev_n, 'gmail_message'))
                        try:
                            await self.metrics.record_email_poll_success(len(raw_list or []))
                        except Exception:
                            pass
                    except Exception as exc:
                        self.logger.debug('Gmail email polling error: %s', exc)
                        try:
                            await self.metrics.record_email_poll_error(1)
                        except Exception:
                            pass

                for ev in events:
                    try:
                        await self.process_event(ev)
                    except Exception as exc:
                        self.logger.debug('Email ingest routing failed: %s', exc)
                    await asyncio.sleep(batch_sleep)

            except Exception as outer:
                self.logger.debug('Email ingest loop iteration failed: %s', outer)
            await asyncio.wait_for(asyncio.sleep(poll_interval), timeout=poll_interval+5)

        self.logger.info('Email ingest loop stopped')

    def _compose_email_event(self, normalized: dict[str, Any], event_type: str) -> dict[str, Any]:
        """Compose an orchestrator-friendly event envelope from normalized email data."""
        eid = normalized.get('event_id') or f"email-{int(time.time()*1000)}"
        headers = normalized.get('headers') or {}
        body_preview = normalized.get('body_preview')
        subject = (normalized.get('email') or {}).get('subject') or normalized.get('subject')
        sender = (normalized.get('email') or {}).get('from') or headers.get('from')
        has_attachments = (normalized.get('email') or {}).get('has_attachments') or False
        env = {
            'id': eid,
            'source': 'email',
            'event_type': event_type,
            'severity': 'low',
            'timestamp': normalized.get('ts') or time.time(),
            'details': {
                'subject': subject,
                'from': sender,
                'headers': headers,
                'body_preview': body_preview,
                'has_attachments': has_attachments,
                'ingest_source': normalized.get('ingest_source'),
            },
            'tenant_id': normalized.get('tenant_id') or 'default',
            'domain': 'email',
            'ingest_source': normalized.get('ingest_source') or 'email',
            'headers': headers,
            'body_preview': body_preview,
            'subject': subject,
        }
        return env


__all__ = ['SecurityOrchestrator', 'ProcessingResult', 'get_orchestrator', 'set_orchestrator']

# ---------------------------------------------------------------------------
# Module-level singleton for cross-module access to the running orchestrator
# ---------------------------------------------------------------------------
_ORCHESTRATOR_INSTANCE: 'SecurityOrchestrator | None' = None


def get_orchestrator() -> 'SecurityOrchestrator | None':
    """Return the running SecurityOrchestrator instance (or None if not started)."""
    return _ORCHESTRATOR_INSTANCE


def set_orchestrator(instance: 'SecurityOrchestrator | None') -> None:
    """Register (or clear) the active orchestrator instance."""
    global _ORCHESTRATOR_INSTANCE
    _ORCHESTRATOR_INSTANCE = instance
