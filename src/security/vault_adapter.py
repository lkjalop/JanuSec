from __future__ import annotations

import os
import json
import logging
from typing import Optional

LOG = logging.getLogger(__name__)

try:
    import httpx
except Exception:
    httpx = None


def get_secret_from_vault(name: str) -> Optional[str]:
    """Attempt to read `name` from Vault using VAULT_ADDR and VAULT_TOKEN.

    If `VAULT_ADDR` not set, support a developer-friendly simulation file
    `data/vault_sim.json` for local testing.
    """
    addr = os.getenv('VAULT_ADDR')
    if not addr:
        # developer local sim
        sim = os.path.join('data', 'vault_sim.json')
        if os.path.exists(sim):
            try:
                with open(sim, 'r', encoding='utf-8') as fh:
                    store = json.load(fh)
                    return store.get(name)
            except Exception:
                LOG.exception('failed to read vault_sim')
                return None
        return None

    token = os.getenv('VAULT_TOKEN')
    if httpx is None:
        LOG.warning('httpx missing; cannot contact Vault')
        return None

    try:
        client = httpx.Client(timeout=10)
        # Read from KV v2 at /v1/secret/data/<name>
        path = f"{addr.rstrip('/')}/v1/secret/data/{name}"
        headers = {}
        if token:
            headers['X-Vault-Token'] = token
        r = client.get(path, headers=headers)
        if r.status_code == 200:
            data = r.json()
            return data.get('data', {}).get('data', {}).get('value')
    except Exception:
        LOG.exception('vault request failed')
    return None
