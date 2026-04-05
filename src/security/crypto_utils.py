from __future__ import annotations

import os
from src.security.secret_provider import get_secret
import base64
import logging
from typing import Optional

LOG = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet
except Exception:
    Fernet = None  # type: ignore


def _get_key() -> Optional[bytes]:
    key = get_secret('INTEGRATIONS_ENCRYPTION_KEY') or os.getenv('INTEGRATIONS_ENCRYPTION_KEY')
    if key:
        try:
            return key.encode()
        except Exception:
            return None

    # If cryptography is not available, fail fast unless explicitly allowed
    if Fernet is None:
        allow = os.getenv('ALLOW_INSECURE_FALLBACK')
        if allow and allow in ('1', 'true', 'yes'):
            LOG.warning('cryptography not installed; using insecure fallback (ALLOWED by ALLOW_INSECURE_FALLBACK)')
            return None
        raise RuntimeError('cryptography package required for secure encryption. Install cryptography or set ALLOW_INSECURE_FALLBACK=1 for dev only')

    # generate temporary in-memory key and warn (not for production)
    k = Fernet.generate_key()
    LOG.warning('INTEGRATIONS_ENCRYPTION_KEY not set; generated ephemeral key (use env for persistence)')
    return k


def encrypt_secret(plaintext: str) -> str:
    key = _get_key()
    if key and Fernet is not None:
        f = Fernet(key)
        return f.encrypt(plaintext.encode()).decode()
    # fallback: simple reversible base64 XOR (not secure) using key derived from env
    salt = (os.getenv('INTEGRATIONS_ENCRYPTION_KEY') or 'fallback_key').encode()
    data = plaintext.encode()
    out = bytes([b ^ salt[i % len(salt)] for i, b in enumerate(data)])
    return base64.urlsafe_b64encode(out).decode()


def decrypt_secret(ciphertext: str) -> str:
    key = _get_key()
    if key and Fernet is not None:
        f = Fernet(key)
        try:
            return f.decrypt(ciphertext.encode()).decode()
        except Exception:
            LOG.exception('fernet decrypt failed')
            return ''
    try:
        raw = base64.urlsafe_b64decode(ciphertext.encode())
        salt = (os.getenv('INTEGRATIONS_ENCRYPTION_KEY') or 'fallback_key').encode()
        out = bytes([b ^ salt[i % len(salt)] for i, b in enumerate(raw)])
        return out.decode()
    except Exception:
        LOG.exception('fallback decrypt failed')
        return ''
