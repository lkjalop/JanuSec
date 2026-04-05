import requests
import time
import logging
from typing import Callable, Any, Dict, Optional

from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)


def request_with_auto_refresh(tenant_id: str, make_request: Callable[[str], Any], provider: str = 'msgraph', max_attempts: int = 2) -> Any:
    """Helper that loads access token for tenant, calls `make_request(token)` and if a 401 occurs
    attempts to refresh the token using TenantStore (if refresh_token present) and retries once.
    `make_request` should accept a single arg `access_token` and return a `requests.Response`-like object.
    """
    store = TenantStore()
    tokens = store.load_tokens(tenant_id) or {}
    access = tokens.get('access_token')
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        try:
            resp = make_request(access)
            # If resp looks like a requests.Response
            if hasattr(resp, 'status_code') and resp.status_code == 401:
                # try refresh
                if tokens.get('refresh_token'):
                    try:
                        # Attempt refresh via tenant store backend or connector refresh
                        refreshed = store.try_refresh_tokens(tenant_id)
                        if refreshed:
                            tokens = store.load_tokens(tenant_id)
                            access = tokens.get('access_token')
                            continue
                    except Exception:
                        logger.exception('Token refresh attempt failed')
                # No refresh available
                return resp
            return resp
        except requests.HTTPError as he:
            logger.debug('HTTP error during request_with_auto_refresh: %s', he)
            raise
        except Exception as e:
            logger.debug('non-http error in request_with_auto_refresh: %s', e)
            raise
    return None
