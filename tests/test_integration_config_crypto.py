import os
import json
import tempfile
import pytest

from src.security.crypto_utils import encrypt_secret, decrypt_secret
from src.integrations.sandbox.generic_provider import _load_config, GenericSandboxProvider


def test_encrypt_decrypt_roundtrip(monkeypatch, tmp_path):
    # generate a temporary key for test
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('INTEGRATIONS_ENCRYPTION_KEY', key)

    # simulate saving config file with api_key
    cfg = {'base_url': 'https://fake', 'api_key': 'supersecret', 'api_key_header': 'X-API-KEY'}
    p = tmp_path / 'data' / 'integrations'
    p.mkdir(parents=True)
    fp = p / 'crypto_test.json'
    # encrypt before writing
    cfg['api_key'] = encrypt_secret('supersecret')
    cfg['_api_key_encrypted'] = True
    fp.write_text(json.dumps(cfg))

    # monkeypatch loader path
    monkeypatch.chdir(tmp_path)
    loaded = _load_config('crypto_test')
    assert loaded.get('_api_key_encrypted') is True

    # GenericSandboxProvider should decrypt and set header
    provider = GenericSandboxProvider('crypto_test')
    # Provider headers should include X-API-KEY with cleartext secret
    assert provider.headers.get('X-API-KEY') == 'supersecret'
