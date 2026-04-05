"""Lightweight shim for the 'rsa' package used in tests.

This module implements the minimal `newkeys()` API and key objects with
`save_pkcs1()` so tests that generate ephemeral RSA keys for DKIM/ARC
signing can run without installing the external `rsa` package.

It uses the `cryptography` package to create keys and serialize them in
PKCS#1 (TraditionalOpenSSL) PEM format which is compatible with dkimpy.
"""
from __future__ import annotations
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.backends import default_backend as _default_backend
except Exception as e:
    raise ImportError("cryptography is required for the rsa shim") from e


class _PrivKey:
    def __init__(self, privkey: _rsa.RSAPrivateKey):
        self._priv = privkey

    def save_pkcs1(self) -> bytes:
        # Serialize to PKCS#1 PEM (TraditionalOpenSSL)
        return self._priv.private_bytes(
            encoding=_serialization.Encoding.PEM,
            format=_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=_serialization.NoEncryption(),
        )


class _PubKey:
    def __init__(self, pubkey: _rsa.RSAPublicKey):
        self._pub = pubkey

    def save_pkcs1(self) -> bytes:
        # Serialize public key in SubjectPublicKeyInfo PEM (compatible with many tools)
        return self._pub.public_bytes(
            encoding=_serialization.Encoding.PEM,
            format=_serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def newkeys(key_size: int = 1024) -> Tuple[_PubKey, _PrivKey]:
    """Generate a new RSA keypair and return (pub, priv).

    The API mirrors the minimal behaviour used by tests: the private key
    object supports `save_pkcs1()` returning PEM bytes acceptable to
    dkimpy for signing.
    """
    priv = _rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=_default_backend())
    pub = priv.public_key()
    return (_PubKey(pub), _PrivKey(priv))
