import pytest
from src.security.storage_paths import storage_id, storage_path


@pytest.mark.parametrize('identifier', ['../outside', '..\\outside', 'C:\\outside', '/outside', 'a/b', 'a\\b', 'a:stream', '.', '..', 'CON', 'aux.json', 'lpt1', 'a.', 'a\n'])
def test_storage_ids_reject_traversal_and_windows_aliases(identifier):
    with pytest.raises(ValueError):
        storage_id(identifier)


def test_encrypted_store_cannot_touch_outside_file(tmp_path, monkeypatch):
    from src.integrations import tenant_store
    root = tmp_path / 'store'
    root.mkdir()
    monkeypatch.setattr(tenant_store, 'STORE_DIR', str(root))
    store = tenant_store.FileSecretBackend()
    outside = tmp_path / 'outside.json.enc'
    outside.write_bytes(b'unchanged')
    for key in ('../outside', '..\\outside'):
        for operation in (lambda: store.save(key, {}), lambda: store.load(key), lambda: store.delete(key)):
            with pytest.raises(ValueError):
                operation()
    assert outside.read_bytes() == b'unchanged'
    store.save('tenants/acme/tokens', {'fixture': True})
    assert store.load('tenants/acme/tokens') == {'fixture': True}


def test_polling_store_does_not_alias_invalid_tenant(tmp_path):
    from src.integrations.polling_state import PollingStateStore
    store = PollingStateStore(str(tmp_path))
    store.save_state('acme_ops', 'graph', {'checkpoint': 'safe'})
    with pytest.raises(ValueError):
        store.save_state('acme/ops', 'graph', {'checkpoint': 'overwrite'})
    assert store.load_state('acme_ops', 'graph') == {'checkpoint': 'safe'}


def test_resolved_symlink_escape_is_denied(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    root = tmp_path / 'root'
    root.mkdir()
    try:
        (root / 'linked').symlink_to(outside, target_is_directory=True)
    except OSError:
        # Windows accounts can lack symlink privilege; junctions are separately
        # subject to the same realpath containment check.
        return
    with pytest.raises(ValueError):
        storage_path(root, 'linked')
