import os
import json
import tempfile
from fastapi.testclient import TestClient
try:
    import jwt
except Exception:
    jwt = None
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from src.api.server import app


def generate_rsa_key_and_jwks():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = key.public_key()
    nums = pub.public_numbers()
    # Use PyJWT's jwk_from_pem helper by exporting PEM
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Build a minimal JWKS containing the public key using jwt library helpers
    jwk = jwt.PyJWK.from_pem(pub_pem)
    jwks = {'keys': [jwk.to_dict()]}
    return priv_pem, jwks


def test_gmail_jwt_verification(tmp_path, monkeypatch):
    if jwt is None:
        import pytest
        pytest.skip('pyjwt not installed in test environment')
    priv_pem, jwks = generate_rsa_key_and_jwks()
    jwks_file = tmp_path / 'jwks.json'
    jwks_file.write_text(json.dumps(jwks))
    jwks_url = f'file:///{jwks_file.as_posix()}'
    monkeypatch.setenv('GMAIL_PUBSUB_JWKS_URL', jwks_url)
    # create token
    payload = {'sub': 'test', 'aud': None}
    token = jwt.encode(payload, priv_pem, algorithm='RS256')

    client = TestClient(app)
    body = {'message': {'attributes': {'jwt': token}}}
    resp = client.post('/api/v1/subscriptions/gmail/callback', json=body)
    assert resp.status_code == 200
