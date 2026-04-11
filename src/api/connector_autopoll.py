"""connector_autopoll.py — Background auto-poll scheduler for AWS/Azure connectors.

Enabled via environment variables:
    CONNECTOR_AUTOPOLL_ENABLED=1        — master switch
    CONNECTOR_AUTOPOLL_INTERVAL=120     — seconds between poll cycles (default 120)
    CONNECTOR_AUTOPOLL_TENANTS=t1,t2    — comma-separated tenant IDs (default "default")
    CONNECTOR_AUTOPOLL_PROVIDERS=aws,azure  — which providers to poll (default both)
    CONNECTOR_AUTOPOLL_API_KEY=<key>    — API key used for internal poll calls

Each enabled provider/connector is polled by calling the existing
connector_poll() logic directly (no HTTP round-trip), so auth/config are
re-read from ConnectorConfigStore on every cycle.

The scheduler uses asyncio and is safe to cancel.  It is registered by
_register_background_schedulers() in app.py.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Connectors polled per provider (extend as you add new connectors)
_AZURE_CONNECTORS = ['entra_signin', 'entra_audit', 'defender_cloud', 'eventhub', 'nsg_flow', 'azure_activity']
_AWS_CONNECTORS   = ['cloudtrail', 'guardduty', 'securityhub', 'vpcflow', 'detective', 'macie']


def _autopoll_enabled() -> bool:
    return os.getenv('CONNECTOR_AUTOPOLL_ENABLED', '0').lower() in ('1', 'true', 'yes')


def _poll_interval() -> int:
    try:
        return max(30, int(os.getenv('CONNECTOR_AUTOPOLL_INTERVAL', '120') or '120'))
    except Exception:
        return 120


def _tenants() -> List[str]:
    raw = os.getenv('CONNECTOR_AUTOPOLL_TENANTS', 'default') or 'default'
    return [t.strip() for t in raw.split(',') if t.strip()]


def _providers() -> List[str]:
    raw = os.getenv('CONNECTOR_AUTOPOLL_PROVIDERS', 'aws,azure') or 'aws,azure'
    return [p.strip().lower() for p in raw.split(',') if p.strip()]


def _autopoll_api_key() -> str:
    key = (
        os.getenv('CONNECTOR_AUTOPOLL_API_KEY')
        or os.getenv('API_KEY')
        or os.getenv('DEFAULT_API_KEY')
    )
    if not key:
        # Fail closed in production — operators must configure an API key.
        # Only fall back to devkey123 when TEST_HELPERS_ENABLED is explicitly set
        # to avoid shipping an open back-door in production deployments.
        if os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1', 'true', 'yes'}:
            return 'devkey123'
        import warnings
        warnings.warn(
            'CONNECTOR_AUTOPOLL_API_KEY is not configured. '
            'Connector auto-poll will fail authentication. '
            'Set CONNECTOR_AUTOPOLL_API_KEY or API_KEY environment variable.',
            RuntimeWarning,
            stacklevel=2,
        )
        return ''
    return key


def _connectors_for_provider(provider: str) -> List[str]:
    raw = os.getenv(f'CONNECTOR_AUTOPOLL_{provider.upper()}_CONNECTORS', '')
    if raw:
        return [c.strip() for c in raw.split(',') if c.strip()]
    return _AZURE_CONNECTORS if provider == 'azure' else _AWS_CONNECTORS


def _poll_one(app: Any, tenant: str, provider: str, connector: str, api_key: str) -> Dict[str, Any]:
    """Run a single poll cycle in a thread-safe way by calling the connector logic directly."""
    try:
        from src.api.routes.connectors import (
            ConnectorPollRequest,
            _aws_connector,
            _azure_connector,
            _dedupe_events,
            _append_events,
            _emit_connector_decisions,
        )
        from src.api.runtime_state import (
            get_server_runtime_state,
            update_connector_health,
            persist_tenant_runtime,
        )
        from src.connectors.resilience import RetryPolicy, execute_with_resilience, load_runtime_state
        from src.integrations.polling_state import PollingStateStore

        runtime = get_server_runtime_state(app)
        body = ConnectorPollRequest(limit=500)
        connector_id = f'{provider}:{connector}'
        state_store = PollingStateStore()

        if provider == 'aws':
            conn, fetcher = _aws_connector(connector, body)
        elif provider == 'azure':
            conn, fetcher = _azure_connector(connector, body, tenant)
        else:
            return {'ok': False, 'error': 'unknown_provider'}

        # Validate config before attempting real poll (avoid noisy errors for unconfigured tenants)
        if provider == 'azure':
            missing = conn.cfg.validate_for(connector)
            if missing:
                logger.debug('autopoll: %s/%s/%s skipped — missing config: %s', tenant, provider, connector, missing)
                return {'ok': False, 'skipped': True, 'missing': missing}

        events = execute_with_resilience(
            lambda: fetcher() or [],
            store=state_store,
            tenant_id=tenant,
            provider=provider,
            connector=connector,
            policy=RetryPolicy(),
        )
        events, dup_count = _dedupe_events(runtime, tenant, provider, connector, events)
        _append_events(runtime, tenant, connector, events)
        emitted = _emit_connector_decisions(provider, connector, events)
        runtime_state = load_runtime_state(state_store, tenant, provider, connector)
        update_connector_health(
            runtime,
            tenant,
            connector_id,
            provider=provider,
            status='ok',
            ok=True,
            last_count=len(events),
            checkpoint=getattr(conn, 'ck', {}),
        )
        persist_tenant_runtime(runtime, tenant)
        logger.info(
            'autopoll: %s/%s/%s → %d events, %d decisions, %d dupes suppressed',
            tenant, provider, connector, len(events), emitted, dup_count,
        )
        return {'ok': True, 'ingested': len(events), 'decisions': emitted, 'duplicates': dup_count}
    except Exception as exc:
        logger.warning('autopoll: %s/%s/%s failed: %s', tenant, provider, connector, exc)
        return {'ok': False, 'error': str(exc)}


async def _autopoll_loop(app: Any) -> None:  # pragma: no cover
    """Main auto-poll coroutine. Runs until cancelled."""
    interval = _poll_interval()
    api_key = _autopoll_api_key()
    logger.info('autopoll: starting — interval=%ds providers=%s tenants=%s', interval, _providers(), _tenants())

    while True:
        try:
            tenants = _tenants()
            providers = _providers()
            for tenant in tenants:
                for provider in providers:
                    for connector in _connectors_for_provider(provider):
                        try:
                            await asyncio.to_thread(_poll_one, app, tenant, provider, connector, api_key)
                        except Exception as exc:
                            logger.debug('autopoll: thread error %s/%s/%s: %s', tenant, provider, connector, exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning('autopoll: cycle error: %s', exc)

        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.info('autopoll: cancelled — shutting down')
            return


def register_autopoll(app: Any) -> None:
    """Register the auto-poll background task with the FastAPI app.

    Called from _register_background_schedulers() in app.py.  No-op when
    CONNECTOR_AUTOPOLL_ENABLED is not set.
    """
    if not _autopoll_enabled():
        logger.debug('autopoll: disabled (set CONNECTOR_AUTOPOLL_ENABLED=1 to enable)')
        return
    if os.getenv('PYTEST_CURRENT_TEST') or os.getenv('FAST_TEST_MODE', '').lower() in ('1', 'true', 'yes'):
        logger.debug('autopoll: skipped in test mode')
        return

    async def _start() -> None:  # pragma: no cover
        await asyncio.sleep(5)  # brief delay so app fully starts before first poll
        task = asyncio.create_task(_autopoll_loop(app))
        # Store reference so it can be cancelled on shutdown
        try:
            if not hasattr(app.state, '_autopoll_tasks'):
                app.state._autopoll_tasks = []
            app.state._autopoll_tasks.append(task)
        except Exception:
            pass

    app.add_event_handler('startup', lambda: asyncio.create_task(_start()))
    logger.info('autopoll: registered (interval=%ds)', _poll_interval())
