from __future__ import annotations

import json
from typing import Any, Dict, Optional

from src.integrations.tenant_store import TenantStore


class ConnectorConfigStore:
    """Persist non-token connector configuration per tenant/provider/connector.

    Uses the existing tenant kv store so private-cloud deployments keep a single
    persistence primitive for connector config, checkpoints, and auth material.
    """

    def __init__(self, tenant_store: Optional[TenantStore] = None):
        self._tenant_store = tenant_store or TenantStore()

    def _provider_key(self, provider: str) -> str:
        return f'connector_config:{provider}'

    def _connector_key(self, connector: str) -> str:
        return f'connector:{connector}'

    def load(self, tenant_id: str, provider: str, connector: str) -> Dict[str, Any]:
        raw = self._tenant_store.load_cursor(tenant_id, self._provider_key(provider), self._connector_key(connector))
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def save(self, tenant_id: str, provider: str, connector: str, config: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(config or {})
        self._tenant_store.save_cursor(
            tenant_id,
            self._provider_key(provider),
            self._connector_key(connector),
            json.dumps(payload, sort_keys=True, separators=(',', ':')),
        )
        return payload

