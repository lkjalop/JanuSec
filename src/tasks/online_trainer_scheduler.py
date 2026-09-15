from __future__ import annotations

import asyncio
import logging
import os

logger = logging.getLogger(__name__)


def register_online_trainer_scheduler(app, interval_seconds: int = 86400):
    """Register a periodic scheduler that triggers ClosedLoopManager.propose_weights().

    This scheduler is opt-in via the `ONLINE_TRAINER_SCHED_ENABLED` env var.
    """
    enabled = os.getenv('ONLINE_TRAINER_SCHED_ENABLED', '0').lower() in {'1', 'true', 'yes'}
    if not enabled:
        logger.debug('Online trainer scheduler not enabled')
        return

    async def _loop():
        from src.ml.closed_loop_manager import ClosedLoopManager
        clm = ClosedLoopManager()
        while True:
            try:
                ready = False
                try:
                    ready = clm.ready_to_learn()
                except Exception:
                    try:
                        ready = getattr(clm, 'ready', lambda: False)()
                    except Exception:
                        ready = False
                if ready:
                    try:
                        # propose_weights is async
                        res = await clm.propose_weights()
                        summary = res.get('summary') if isinstance(res, dict) else str(res)
                        logger.info('Online trainer proposed candidate: %s', summary)
                    except Exception:
                        logger.exception('Failed to propose weights')
            except Exception:
                logger.exception('Online trainer scheduler iteration failed')
            await asyncio.sleep(max(10, interval_seconds))

    try:
        app.add_event_handler('startup', lambda: asyncio.create_task(_loop()))
    except Exception:
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_loop())
        except Exception:
            logger.exception('Failed to start online trainer scheduler')
