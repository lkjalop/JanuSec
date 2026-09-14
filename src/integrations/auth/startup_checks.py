"""Startup checks for token encryption key and secret backends."""
import logging
import os

logger = logging.getLogger(__name__)


def check_encryption_key():
    # TenantStore uses a file key for FileSecretBackend; TokenStore uses Fernet.generate_key by default.
    # Warn if cryptography not installed or key file missing when using file backend.
    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception:
        logger.warning('cryptography.Fernet not available; token encryption will use base64 fallback')
        return
    key_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tenant_store', 'fernet.key')
    key_path = os.path.normpath(key_path)
    if not os.path.exists(key_path):
        logger.warning('TenantStore encryption key not present at %s; create one or set SECRET_BACKEND to vault', key_path)


__all__ = ['check_encryption_key']
