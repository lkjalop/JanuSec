import pytest
from cryptography.fernet import Fernet, InvalidToken

from src.integrations.fernet_rotation import rotate_file_store


def test_rotation_preserves_payload_and_rejects_old_key(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    key = Fernet.generate_key()
    (store / "fernet.key").write_bytes(key)
    for name in ["one", "two"]:
        (store / f"{name}.json.enc").write_bytes(Fernet(key).encrypt(name.encode()))
    result = rotate_file_store(store, tmp_path / "recovery")
    assert result["encrypted_files"] == 2 and result["payloads_preserved"]
    for name in ["one", "two"]:
        ciphertext = (store / f"{name}.json.enc").read_bytes()
        assert Fernet((store / "fernet.key").read_bytes()).decrypt(ciphertext) == name.encode()
        with pytest.raises(InvalidToken):
            Fernet(key).decrypt(ciphertext)
        assert Fernet(key).decrypt((tmp_path / "recovery" / f"{name}.json.enc").read_bytes()) == name.encode()


def test_corrupt_ciphertext_leaves_key_unchanged(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    key = Fernet.generate_key()
    (store / "fernet.key").write_bytes(key)
    (store / "broken.json.enc").write_bytes(b"not-a-token")
    with pytest.raises(InvalidToken):
        rotate_file_store(store, tmp_path / "recovery")
    assert (store / "fernet.key").read_bytes() == key
    assert not (tmp_path / "recovery").exists()


def test_interrupted_rotation_fails_closed(tmp_path, monkeypatch):
    from src.integrations import tenant_store
    monkeypatch.setattr(tenant_store, "STORE_DIR", str(tmp_path))
    (tmp_path / ".rotation-in-progress").touch()
    with pytest.raises(tenant_store.SecretBackendError):
        tenant_store.FileSecretBackend()
