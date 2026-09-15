from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Request

from src.api.runtime_state import get_server_runtime_state, get_connector_health
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/status")


def _build_dep_status() -> Dict[str, Any]:
    """Check optional heavy dependencies and connector readiness."""
    deps: Dict[str, Any] = {}

    # AWS
    try:
        from src.connectors.aws.sqs_consumer import SQSPoller
        from src.connectors.aws.kinesis_consumer import KinesisShardConsumer
        ok_sqs, msg_sqs = SQSPoller.check_ready()
        ok_kin, msg_kin = KinesisShardConsumer.check_ready()
        deps['aws_sqs'] = {'ready': ok_sqs, 'detail': msg_sqs}
        deps['aws_kinesis'] = {'ready': ok_kin, 'detail': msg_kin}
    except Exception as exc:
        deps['aws'] = {'ready': False, 'detail': str(exc)}

    # Azure
    try:
        from src.connectors.azure.entra_id import EntraIDConnector
        from src.connectors.azure.defender_cloud import DefenderCloudConnector
        from src.connectors.azure.sentinel_workspace import SentinelWorkspaceConnector
        ok_e, msg_e = EntraIDConnector.check_ready()
        ok_d, msg_d = DefenderCloudConnector.check_ready()
        ok_s, msg_s = SentinelWorkspaceConnector.check_ready()
        deps['azure_entra'] = {'ready': ok_e, 'detail': msg_e}
        deps['azure_defender'] = {'ready': ok_d, 'detail': msg_d}
        deps['azure_sentinel'] = {'ready': ok_s, 'detail': msg_s}
    except Exception as exc:
        deps['azure'] = {'ready': False, 'detail': str(exc)}

    # Kafka
    try:
        import confluent_kafka  # type: ignore  # noqa: F401
        deps['kafka'] = {'ready': True, 'detail': 'ok'}
    except ImportError:
        deps['kafka'] = {'ready': False, 'detail': 'confluent-kafka not installed; pip install confluent-kafka'}

    return deps


def _runtime_projection(entry: Dict[str, Any], now: float) -> Dict[str, Any]:
    runtime_state = entry.get('runtime_state') or {}
    metadata = entry.get('metadata') or {}
    open_until = runtime_state.get('open_until')
    circuit_open = False
    try:
        circuit_open = bool(open_until and float(open_until) > now)
    except Exception:
        circuit_open = False
    return {
        'last_duplicate_count': entry.get('last_duplicate_count', metadata.get('last_duplicate_count', 0)),
        'last_latency_ms': entry.get('last_latency_ms', runtime_state.get('last_latency_ms')),
        'runtime_state': runtime_state,
        'circuit_open': circuit_open,
        'circuit_open_until': open_until,
    }


@router.get("/connectors")
def connectors_status(
    request: Request,
    tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
) -> Dict[str, Any]:
    runtime = get_server_runtime_state(request.app)
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or 'default'
    health = get_connector_health(runtime, tenant)
    now = time.time()
    connectors = []
    for name, entry in health.items():
        if not isinstance(entry, dict):
            continue
        connectors.append(
            {
                'name': name,
                'provider': entry.get('provider'),
                'healthy': bool(entry.get('ok', False)),
                'status': entry.get('status', 'unknown'),
                'last_ok_ts': entry.get('last_ok_ts'),
                'last_error': entry.get('last_error'),
                'last_poll_ts': entry.get('last_poll_ts'),
                'last_count': entry.get('last_count', 0),
                'checkpoint': entry.get('checkpoint') or {},
                'authenticated': bool(entry.get('authenticated')),
                'receiving_events': bool(entry.get('receiving_events')),
                'checkpoint_healthy': bool(entry.get('checkpoint_healthy')),
                'beta_ready': bool(entry.get('beta_ready')),
                'freshness': entry.get('freshness') or {},
                'seconds_since_ok': (now - float(entry.get('last_ok_ts'))) if entry.get('last_ok_ts') else None,
                **_runtime_projection(entry, now),
            }
        )
    return {
        'tenant': tenant,
        'connectors': connectors,
        'dependency_status': {
            'redis': {'healthy': True},
            'runtime_state': {'healthy': True},
            **_build_dep_status(),
        },
    }
