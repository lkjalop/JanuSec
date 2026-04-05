from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class AzureConnectorConfig:
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    subscription_id: Optional[str] = None
    checkpoint_dir: str | None = None
    eventhub_namespace: Optional[str] = None
    eventhub_name: Optional[str] = None
    eventhub_connection_string: Optional[str] = None
    eventhub_consumer_group: Optional[str] = None
    graph_base_url: Optional[str] = None
    defender_base_url: Optional[str] = None
    auth_mode: Optional[str] = None

    def __post_init__(self) -> None:
        self.tenant_id = self.tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = self.client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = self.client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.subscription_id = self.subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        self.checkpoint_dir = self.checkpoint_dir or os.getenv('CONNECTORS_CHECKPOINT_DIR', 'data/checkpoints')
        self.eventhub_namespace = self.eventhub_namespace or os.getenv('AZURE_EVENTHUB_NAMESPACE')
        self.eventhub_name = self.eventhub_name or os.getenv('AZURE_EVENTHUB_NAME')
        self.eventhub_connection_string = self.eventhub_connection_string or os.getenv('AZURE_EVENTHUB_CONNECTION_STRING')
        self.eventhub_consumer_group = self.eventhub_consumer_group or os.getenv('AZURE_EVENTHUB_CONSUMER_GROUP') or '$Default'
        self.graph_base_url = self.graph_base_url or os.getenv('AZURE_GRAPH_BASE_URL') or 'https://graph.microsoft.com/v1.0'
        self.defender_base_url = self.defender_base_url or os.getenv('AZURE_DEFENDER_BASE_URL') or 'https://management.azure.com'
        self.auth_mode = self.auth_mode or os.getenv('AZURE_AUTH_MODE') or 'client_secret'

    @classmethod
    def from_mapping(cls, data: Dict[str, Any] | None) -> 'AzureConnectorConfig':
        payload = dict(data or {})
        return cls(
            tenant_id=payload.get('tenant_id'),
            client_id=payload.get('client_id'),
            client_secret=payload.get('client_secret'),
            subscription_id=payload.get('subscription_id'),
            checkpoint_dir=payload.get('checkpoint_dir'),
            eventhub_namespace=payload.get('eventhub_namespace'),
            eventhub_name=payload.get('eventhub_name'),
            eventhub_connection_string=payload.get('eventhub_connection_string'),
            eventhub_consumer_group=payload.get('eventhub_consumer_group'),
            graph_base_url=payload.get('graph_base_url'),
            defender_base_url=payload.get('defender_base_url'),
            auth_mode=payload.get('auth_mode'),
        )

    def validate_for(self, connector: str) -> list[str]:
        missing: list[str] = []
        if connector == 'eventhub':
            if not self.eventhub_connection_string:
                missing.append('eventhub_connection_string (env: AZURE_EVENTHUB_CONNECTION_STRING)')
            if not self.eventhub_name:
                missing.append('eventhub_name (env: AZURE_EVENTHUB_NAME)')
        elif connector in {'entra_signin', 'entra_audit'}:
            if not self.tenant_id:
                missing.append('tenant_id (env: AZURE_TENANT_ID)')
            if self.auth_mode == 'client_secret':
                if not self.client_id:
                    missing.append('client_id (env: AZURE_CLIENT_ID)')
                if not self.client_secret:
                    missing.append('client_secret (env: AZURE_CLIENT_SECRET)')
        elif connector == 'defender_cloud':
            if not self.subscription_id:
                missing.append('subscription_id (env: AZURE_SUBSCRIPTION_ID)')
            if self.auth_mode == 'client_secret':
                if not self.client_id:
                    missing.append('client_id (env: AZURE_CLIENT_ID)')
                if not self.client_secret:
                    missing.append('client_secret (env: AZURE_CLIENT_SECRET)')
        elif connector == 'sentinel':
            if not self.tenant_id:
                missing.append('tenant_id (env: AZURE_TENANT_ID)')
            if self.auth_mode == 'client_secret':
                if not self.client_id:
                    missing.append('client_id (env: AZURE_CLIENT_ID)')
                if not self.client_secret:
                    missing.append('client_secret (env: AZURE_CLIENT_SECRET)')
        if missing:
            logger.warning(
                'Azure connector (%s): missing credentials — %s. '
                'Configure a service principal (AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID) '
                'or enable managed identity (AZURE_AUTH_MODE=managed_identity).',
                connector, ', '.join(missing)
            )
        return missing

    def redacted(self) -> Dict[str, Any]:
        return {
            'tenant_id': self.tenant_id,
            'client_id': self.client_id,
            'subscription_id': self.subscription_id,
            'checkpoint_dir': self.checkpoint_dir,
            'eventhub_namespace': self.eventhub_namespace,
            'eventhub_name': self.eventhub_name,
            'eventhub_consumer_group': self.eventhub_consumer_group,
            'graph_base_url': self.graph_base_url,
            'defender_base_url': self.defender_base_url,
            'auth_mode': self.auth_mode,
            'has_client_secret': bool(self.client_secret),
            'has_eventhub_connection_string': bool(self.eventhub_connection_string),
        }


def _ensure_checkpoint_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def checkpoint_path(name: str, cfg: AzureConnectorConfig) -> str:
    base = cfg.checkpoint_dir or 'data/checkpoints'
    _ensure_checkpoint_dir(base)
    return os.path.join(base, f'azure_{name}.checkpoint.json')


def load_checkpoint(name: str, cfg: AzureConnectorConfig) -> dict:
    p = checkpoint_path(name, cfg)
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        logger.exception('failed to load azure checkpoint')
    return {}


def save_checkpoint(name: str, cfg: AzureConnectorConfig, data: dict) -> None:
    p = checkpoint_path(name, cfg)
    try:
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception:
        logger.exception('failed to save azure checkpoint')


def azure_envelope(raw: Dict[str, Any], source: str, *, tenant_id: Optional[str] = None, subscription_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        'source': source,
        'raw': raw,
        'tenant_id': tenant_id,
        'subscription_id': subscription_id,
        'id': raw.get('id') or raw.get('eventId') or raw.get('EventId'),
    }
