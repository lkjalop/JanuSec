from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from src.security.vault_adapter import get_secret_from_vault


def get_secret(name: str) -> Optional[str]:
    """Resolve a secret by checking (in order):
    - environment variable
    - Docker secrets path /run/secrets/<name>
    - Vault (if USE_VAULT=1)
    - fallback None
    """
    # If configured, attempt Vault first
    use_vault = os.getenv('USE_VAULT')
    if use_vault and use_vault in ('1', 'true', 'yes'):
        try:
            v = get_secret_from_vault(name)
            if v:
                return v
        except Exception:
            pass
    val = os.getenv(name)
    if val:
        return val
    secret_path = Path('/run/secrets') / name
    if secret_path.exists():
        try:
            return secret_path.read_text(encoding='utf-8').strip()
        except Exception:
            return None
    return None
