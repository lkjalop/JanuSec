import os
import time
from typing import Dict


def get_api_key() -> str:
    return os.getenv('TEST_API_KEY', 'devkey123')


def bearer_token_for_tenant(tenant_id: str) -> str:
    # Simple stub - in CI replace with real token generator or mock
    return f"Bearer test-token-{tenant_id}-{int(time.time())}"


def headers_for_tenant(tenant_id: str) -> Dict[str, str]:
    return {
        'x-api-key': get_api_key(),
        'Authorization': bearer_token_for_tenant(tenant_id),
        'x-tenant-id': tenant_id,
    }
