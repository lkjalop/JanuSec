from __future__ import annotations

import logging
import os

from . import runtime_state
from .metrics_init import REGISTRY, ensure_metrics
from typing import TYPE_CHECKING
from typing import Optional

if TYPE_CHECKING:
    from prometheus_client import CollectorRegistry

logger = logging.getLogger(__name__)

_INITIALIZED = False


_LEARNER = None
_DLQ = None

def initialize_platform_components() -> None:
    global _INITIALIZED
    if _INITIALIZED:
        return
    # Determine if we should avoid heavy startup (tests/lite mode)
    def _lite_or_test() -> bool:
        try:
            if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}:
                return True
            # PyTest sets this env var for each running test
            if 'PYTEST_CURRENT_TEST' in os.environ:
                return True
            if os.getenv('SKIP_HEAVY_STARTUP','0').lower() in {'1','true','yes'}:
                return True
        except Exception:
            pass
        return False
    # Ensure base metrics are present
    try:
        ensure_metrics()
    except Exception as exc:
        logger.debug('ensure_metrics failed during startup: %s', exc)
    # Load persisted cost metrics (best-effort)
    try:
        from core.metrics.cost_ledger import get_cost_ledger
        loaded = get_cost_ledger().load_snapshot()
        if loaded:
            logger.info('Cost ledger snapshot loaded: %s records', loaded)
    except Exception as exc:
        logger.debug('Cost ledger snapshot load skipped: %s', exc)
    try:
        from artifact import cost_tracker
        if cost_tracker.load_snapshot():
            logger.info('Daily cost tracker snapshot loaded')
    except Exception as exc:
        logger.debug('Daily cost tracker snapshot load skipped: %s', exc)
    # Discover and register SOAR actions explicitly
    try:
        from src import soar
        if hasattr(soar, 'discover_actions'):
            try:
                soar.discover_actions()
            except Exception:
                logger.debug('soar.discover_actions() failed during startup')
        # Load plugin registry after core actions
        try:
            from src.plugins.loader import load_registry
            reg = load_registry()
            logger.info('Plugin registry loaded (version=%s, soar_actions=%d, extractors=%d)',
                        reg.get('version'), len(reg.get('soar_actions') or {}), len(reg.get('factor_extractors') or {}))
        except Exception as exc:
            logger.debug('Plugin registry load skipped: %s', exc)
    except Exception:
        # best effort: don't break startup if soar package not present
        pass
    # Wire real rules engine explicitly
    try:
        import src.live.rules_engine as live_rules
        # REGISTRY may be None at type-check time; runtime binding is defensive
        live_rules.register_metrics(REGISTRY)  # force explicit binding
        # runtime_state.rules_engine is a runtime-assigned module reference
        runtime_state.rules_engine = live_rules
        try:
            import src.api.server as _server
            _server.rules_engine = live_rules
        except Exception:
            pass
        logger.info('Wired live.rules_engine with metrics into runtime_state')
    except Exception as exc:
        logger.warning('Failed to wire live.rules_engine: %s', exc)
    # Additional module metrics
    try:
        from src.api.decisions_stream import register_metrics as _ds_reg
        _ds_reg(REGISTRY)
    except Exception:
        pass
    try:
        from src.core.embedding.providers import register_metrics as _emb_reg
        _emb_reg(REGISTRY)
    except Exception:
        pass
    try:
        from src.core.actions.dispatcher import register_metrics as _disp_reg
        _disp_reg(REGISTRY)
    except Exception:
        pass
    # Correlation engine metrics registration (idempotent)
    try:
        from src.core.correlation.hunt_correlation import register_metrics as _corr_reg
        _corr_reg(REGISTRY)
    except Exception as exc:
        logger.debug('Correlation metrics registration skipped: %s', exc)
    # Decisions stream metrics registration
    try:
        from src.api.decisions_stream import register_metrics as _ds_reg
        _ds_reg(REGISTRY)
    except Exception as exc:
        logger.debug('Decisions stream metrics registration skipped: %s', exc)
    # Wire concrete DB-backed decisions repo if available
    try:
        from repositories.decisions_repo_impl import repo_impl
        # set into api.server global so server persistence uses DB-backed repo
        try:
            import src.api.server as _server
            # Only set if DB adapter seems present (best-effort check)
            from db import database as _db
            if getattr(_db, 'pool', None) is not None or getattr(_db, 'connection', None) is not None:
                _server.decisions_repo = repo_impl
                logger.info('Wired DB-backed decisions_repo into api.server')
                # If the repo_impl exposes ensure_schema, run it to apply migrations (skip in lite/test mode)
                if not _lite_or_test():
                    try:
                        import asyncio
                        # Ensure repo schema only; legacy SQL migrations are retired.
                        try:
                            if hasattr(repo_impl, 'ensure_schema'):
                                asyncio.get_event_loop().run_until_complete(repo_impl.ensure_schema())
                                logger.info('Ensured decisions_repo schema is present')
                        except Exception as exc:
                            logger.warning('Failed to ensure decisions_repo schema: %s', exc)
                    except Exception as exc:
                        logger.warning('Failed to ensure decisions_repo schema: %s', exc)
                # Start persistent learner service if available
                if not _lite_or_test():
                    try:
                        from src.core.learner_service import PersistentLearnerService
                        global _LEARNER
                        _LEARNER = PersistentLearnerService(repo_impl)
                        _LEARNER.start()
                        runtime_state.learner = _LEARNER
                        logger.info('Started PersistentLearnerService background worker')
                    except Exception as exc:
                        logger.debug('PersistentLearnerService failed to start: %s', exc)
                # Start DLQ manager
                if not _lite_or_test():
                    try:
                        from src.core.dlq_manager import DLQManager
                        global _DLQ
                        _DLQ = DLQManager()
                        _DLQ.start()
                        runtime_state.dlq = _DLQ
                        logger.info('Started DLQManager background worker')
                    except Exception as exc:
                        logger.debug('DLQManager failed to start: %s', exc)
        except Exception:
            logger.debug('Failed to wire DB decisions_repo into server (non-fatal)')
    except Exception:
        # Implementation not present or not importable
        pass
    # Embedding providers metrics registration
    try:
        from src.core.embedding.providers import register_metrics as _emb_reg
        _emb_reg(REGISTRY)
    except Exception as exc:
        logger.debug('Embedding providers metrics registration skipped: %s', exc)
    # Action dispatcher metrics
    try:
        from src.core.actions.dispatcher import register_metrics as _disp_reg
        _disp_reg(REGISTRY)
    except Exception as exc:
        logger.debug('Dispatcher metrics registration skipped: %s', exc)
    # TODO: correlation engine metrics registration (when standardized)
    # Optional: start recalibration background stub if configured
    try:
        try:
            interval = int(__import__('os').environ.get('RISK_RECALIBRATE_INTERVAL', '0') or 0)
        except Exception:
            interval = 0
        if interval and interval > 0:
            try:
                from src.core.recalibrator import start_background
                start_background(interval)
                logger.info('Started recalibrator background thread; interval=%s', interval)
            except Exception as exc:
                logger.debug('Failed to start recalibrator thread: %s', exc)
    except Exception:
        pass
    # Background tasks (ingestion gap detector and explanation precompute) are
    # registered centrally by the application via src.api.background_tasks.register_background_tasks.
    # Avoid starting any event loops here to keep initialize_platform_components safe
    # for test and import-time use. The app-level registrant will create tasks
    # on FastAPI startup when not running in lite/test modes.
    _INITIALIZED = True


def shutdown_platform_components():
    global _LEARNER
    global _DLQ
    try:
        import asyncio
        if _LEARNER:
            asyncio.get_event_loop().run_until_complete(_LEARNER.stop())
        if _DLQ:
            asyncio.get_event_loop().run_until_complete(_DLQ.stop())
    except Exception:
        logger.debug('Failed to stop learner cleanly')

__all__ = ['initialize_platform_components']
