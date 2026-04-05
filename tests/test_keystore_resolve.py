import os
import json
import base64
import tempfile

import pytest


def test_resolve_plain_and_env_map(tmp_path, monkeypatch):
    from src.core.keystore import add_key_metadata, get_key_metadata, resolve_key_plaintext
    ks = tmp_path / 'ks.json'
    monkeypatch.setenv('APPROVAL_KEYSTORE_PATH', str(ks))
    # add plain
    add_key_metadata('k1', {'wrap': 'plain', 'plain': 'secret1'})
    assert resolve_key_plaintext('k1') == 'secret1'
    # env map
    monkeypatch.setenv('APPROVAL_KEYSTORE_MAP', json.dumps({'k2': 'envsecret'}))
    assert resolve_key_plaintext('k2') == 'envsecret'


def test_resolve_kms_mock(monkeypatch, tmp_path):
    # create ciphertext base64 of 'kms-plain'
    import base64
    pt = b'kms-plain'
    ctext = base64.b64encode(b'ct-bytes').decode('utf-8')
    ks = tmp_path / 'ks.json'
    monkeypatch.setenv('APPROVAL_KEYSTORE_PATH', str(ks))
    # write metadata
    from src.core.keystore import add_key_metadata
    add_key_metadata('k-kms', {'wrap': 'kms', 'kms_ciphertext': ctext})

    class FakeKMS:
        def decrypt(self, CiphertextBlob=None):
            return {'Plaintext': pt}

    class FakeBoto:
        def client(self, name):
            return FakeKMS()

    monkeypatch.setitem(__import__('sys').modules, 'boto3', FakeBoto())
    from src.core.keystore import resolve_key_plaintext
    assert resolve_key_plaintext('k-kms') == pt.decode('utf-8')
