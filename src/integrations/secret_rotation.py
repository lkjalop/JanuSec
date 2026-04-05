from __future__ import annotations

import logging
import time
from typing import Callable, Dict, Optional

from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)


def rotate_tenant_secret(
    tenant_id: str,
    transform: Optional[Callable[[Dict], Dict]] = None,
    backend: Optional[str] = None,
) -> Dict:
    """Rotate the tenant's stored token payload.

    This helper loads the existing tokens, generates a new placeholder key
    (for demo we just update a rotated_at timestamp) and writes it back to
    the configured backend. In a real system this would re-encrypt or
    rewrap secrets with a new master key and update external vaults.
    """
    store = TenantStore(backend=backend)
    toks = store.load_tokens(tenant_id)
    if toks is None:
        raise RuntimeError("No tokens for tenant")
    toks = dict(toks)
    if callable(transform):
        updated = transform(dict(toks))
        if not isinstance(updated, dict):
            raise RuntimeError("Secret transform must return a dict payload")
        toks = updated
    toks['_rotated_at'] = int(time.time())
    store.save_tokens(tenant_id, toks)
    logger.info('Rotated tokens for tenant %s using backend %s', tenant_id, type(store.backend).__name__)
    return toks

