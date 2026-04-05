from typing import Optional
import os

class SecretProvider:
    """
    Minimal secret provider abstraction.
    - Env-based lookup by default
    - Future: plug Azure Key Vault / AWS Secrets Manager
    """

    def __init__(self, backend: str = "env"):
        self.backend = backend

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if self.backend == "env":
            return os.getenv(key, default)
        # Placeholder for other backends
        return default

    def set(self, key: str, value: str) -> None:
        if self.backend == "env":
            os.environ[key] = value
