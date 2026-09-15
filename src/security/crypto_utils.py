"""Persistent integration encryption; missing or invalid keys fail closed."""
from __future__ import annotations
from src.security.secret_provider import get_secret
from cryptography.fernet import Fernet, InvalidToken


def _get_key() -> bytes:
    key = get_secret('INTEGRATIONS_ENCRYPTION_KEY')
    if not key:
        raise RuntimeError('INTEGRATIONS_ENCRYPTION_KEY must be configured')
    try:
        encoded = key.encode('ascii')
        Fernet(encoded)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise RuntimeError('Invalid integration encryption key') from None
    return encoded


def encrypt_secret(plaintext: str) -> str:
    return Fernet(_get_key()).encrypt(plaintext.encode('utf-8')).decode('ascii')


def decrypt_secret(ciphertext: str) -> str:
    try:
        return Fernet(_get_key()).decrypt(ciphertext.encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError, UnicodeError):
        raise RuntimeError('Integration credential could not be decrypted') from None
