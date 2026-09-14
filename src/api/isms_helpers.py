from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Dict, Any

ARTIFACTS_DIR = os.getenv('ARTIFACTS_DIR') or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'artifacts'))
EVIDENCE_DIR = os.path.join(ARTIFACTS_DIR, 'evidence')
FILES_DIR = os.path.join(ARTIFACTS_DIR, 'files')

os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)


def compute_sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def compute_sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def persist_json(obj: Dict[str, Any], filename: str) -> str:
    path = os.path.join(EVIDENCE_DIR, filename)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    return path


def save_uploaded_file(file_path: str, dest_name: str) -> str:
    dest = os.path.join(FILES_DIR, dest_name)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(file_path, 'rb') as src, open(dest, 'wb') as dst:
        for chunk in iter(lambda: src.read(8192), b''):
            dst.write(chunk)
    return dest


def hmac_sign(message: bytes, secret: str) -> str:
    key = secret.encode('utf-8')
    sig = hmac.new(key, message, digestmod=hashlib.sha256).hexdigest()
    return sig


# RSA sign/verify helpers (optional dependency on cryptography)
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import serialization

    def rsa_sign(message: bytes, private_pem: bytes) -> str:
        priv = serialization.load_pem_private_key(private_pem, password=None)
        sig = priv.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return sig.hex()

    def rsa_verify(message: bytes, signature_hex: str, public_pem: bytes) -> bool:
        pub = serialization.load_pem_public_key(public_pem)
        sig = bytes.fromhex(signature_hex)
        try:
            pub.verify(sig, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False
except Exception:
    def rsa_sign(*a, **k):
        raise NotImplementedError('cryptography package required for RSA signing')

    def rsa_verify(*a, **k):
        raise NotImplementedError('cryptography package required for RSA verify')
