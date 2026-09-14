import asyncio
import json
import secrets
import time
from pathlib import Path

import jwt
import pytest
from fastapi import HTTPException
from cryptography.exceptions import InvalidTag

from src.backup.pilot_state import backup, restore, state_lock
from src.security.runtime_profile import UNSAFE_FLAGS, validate_live_auth_configuration


@pytest.fixture
def live(monkeypatch):
    for name in UNSAFE_FLAGS:
        monkeypatch.delenv(name, raising=False)
    for name in ('JWT_SECRET', 'JWT_ISSUER', 'JWT_AUDIENCE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('ENV', 'production')
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('JANUSEC_RUNTIME_PROFILE', 'production')
    monkeypatch.setenv('STRICT_API_KEY_ENFORCEMENT', '1')
    entry = {'key': secrets.token_urlsafe(48), 'tenant_id': 'pilot-a', 'scopes': ['*']}
    monkeypatch.setenv('API_KEYS_JSON', json.dumps([entry]))
    return entry


def test_live_auth_accepts_tenant_bound_strong_key(live):
    validate_live_auth_configuration()


@pytest.mark.parametrize('flag', UNSAFE_FLAGS)
def test_live_auth_rejects_permissive_settings(live, monkeypatch, flag):
    monkeypatch.setenv(flag, '1')
    with pytest.raises(RuntimeError, match='unsafe flags'):
        validate_live_auth_configuration()


@pytest.mark.parametrize('change', [
    {'tenant_id': None}, {'key': 'devkey123'}, {'key': 'a' * 64}, {'scopes': []},
])
def test_live_auth_rejects_unsafe_credentials(live, monkeypatch, change):
    monkeypatch.setenv('API_KEYS_JSON', json.dumps([{**live, **change}]))
    with pytest.raises(RuntimeError, match='tenant bindings and scopes'):
        validate_live_auth_configuration()


def test_live_auth_rejects_conflicting_profiles(live, monkeypatch):
    monkeypatch.setenv('APP_ENV', 'dev')
    with pytest.raises(RuntimeError, match='conflicting'):
        validate_live_auth_configuration()


def test_production_never_accepts_pytest_auth_bypass(live, monkeypatch):
    from src.security.auth import auth_dependency, require_api_key
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    with pytest.raises(HTTPException):
        asyncio.run(auth_dependency('devkey123', None, []))
    with pytest.raises(HTTPException):
        asyncio.run(require_api_key(None, None))


def test_production_never_relaxes_expired_jwt_under_pytest(live, monkeypatch):
    from src.security.auth import auth_dependency
    secret = secrets.token_urlsafe(48)
    monkeypatch.setenv('JWT_SECRET', secret)
    token = jwt.encode({'sub': 'analyst', 'tenant_id': 'pilot-a', 'exp': time.time() - 60}, secret, algorithm='HS256')
    with pytest.raises(HTTPException):
        asyncio.run(auth_dependency(None, 'Bearer ' + token, []))


def test_production_jwt_requires_expiration_and_ignores_test_secret(live, monkeypatch):
    from src.security.auth import auth_dependency
    secret = secrets.token_urlsafe(48)
    monkeypatch.setenv('JWT_TEST_SECRET', secret)
    token = jwt.encode({'sub': 'analyst', 'tenant_id': 'pilot-a'}, secret, algorithm='HS256')
    with pytest.raises(HTTPException):
        asyncio.run(auth_dependency(None, 'Bearer ' + token, []))
    monkeypatch.setenv('JWT_SECRET', secret)
    with pytest.raises(HTTPException):
        asyncio.run(auth_dependency(None, 'Bearer ' + token, []))


@pytest.fixture
def stored(tmp_path):
    root = tmp_path / 'state'; root.mkdir()
    (root / 'data').mkdir()
    (root / 'data' / 'evidence.bin').write_bytes(b'case evidence\x00')
    (root / 'data' / 'checkpoint.json').write_text('{"cursor":42}')
    (root / 'secrets.json').write_text('{"private":"synthetic secret"}')
    key = tmp_path / 'recovery.key'; key.write_bytes(secrets.token_bytes(32))
    return root, key, tmp_path / 'backup.enc'


def test_complete_encrypted_state_restore(stored, tmp_path):
    root, key, archive = stored
    result = backup(root, archive, key)
    assert result['files'] == 3
    assert b'synthetic secret' not in archive.read_bytes()
    target = tmp_path / 'restored'
    assert restore(archive, target, key)['verified']
    for path in root.rglob('*'):
        if path.is_file() and path.name != '.janusec-state.lock':
            assert (target / path.relative_to(root)).read_bytes() == path.read_bytes()


def test_backup_refuses_running_state(stored):
    root, key, archive = stored
    with state_lock(root), pytest.raises(RuntimeError, match='pilot_state_busy'):
        backup(root, archive, key)
    assert not archive.exists()


@pytest.mark.parametrize('wrong_key', [True, False])
def test_restore_authenticates_before_creating_target(stored, tmp_path, wrong_key):
    root, key, archive = stored
    backup(root, archive, key)
    if wrong_key:
        key.write_bytes(secrets.token_bytes(32))
    else:
        value = bytearray(archive.read_bytes()); value[-20] ^= 1; archive.write_bytes(value)
    target = tmp_path / 'restored'
    with pytest.raises(InvalidTag):
        restore(archive, target, key)
    assert not target.exists()


def test_restore_never_overwrites_existing_state(stored):
    root, key, archive = stored
    backup(root, archive, key)
    before = (root / 'secrets.json').read_bytes()
    with pytest.raises(FileExistsError):
        restore(archive, root, key)
    assert (root / 'secrets.json').read_bytes() == before


def test_backup_rejects_nested_destination_and_key(stored):
    root, key, archive = stored
    with pytest.raises(ValueError, match='outside_state'):
        backup(root, root / 'backup.enc', key)
    with pytest.raises(ValueError, match='outside_state'):
        backup(root, archive, root / 'secrets.json')


def test_v2_checkpoint_directory_does_not_collide_with_legacy_file(tmp_path, monkeypatch):
    from src.core.connectors.checkpoint_store_v2 import CheckpointStoreV2
    from src.integrations.checkpoint_store import CheckpointStore
    legacy = tmp_path / 'legacy.json'
    modern = tmp_path / 'v2'
    monkeypatch.setenv('CONNECTOR_CHECKPOINTS_PATH', str(legacy))
    monkeypatch.setenv('CONNECTOR_CHECKPOINTS_V2_DIR', str(modern))
    CheckpointStore(str(legacy)).save('a', 'cursor-a')
    CheckpointStoreV2().save('provider', 'stream', {'cursor': 'cursor-b'})
    assert CheckpointStore(str(legacy)).load('a') == 'cursor-a'
    assert CheckpointStoreV2().load('provider', 'stream')['cursor'] == 'cursor-b'


@pytest.fixture
def ingest_store(tmp_path, monkeypatch):
    from src.core.ingest import store
    monkeypatch.setattr(store, '_conn', None)
    monkeypatch.setattr(store, '_DB_PATH', str(tmp_path / 'ingest.duckdb'))
    monkeypatch.setattr(store, '_RAW_ROOT', str(tmp_path / 'raw'))
    yield store
    if store._conn is not None:
        store._conn.close()


def test_restored_raw_capture_uses_current_owned_root(ingest_store, tmp_path, monkeypatch):
    store = ingest_store
    store.create_job('assessment-portable', org='pilot-a')
    directory = Path(store.raw_dir_for('assessment-portable', tenant_id='pilot-a'))
    source = directory / 'events.csv'; source.write_bytes(b'user\nalice\n')
    store.register_file('assessment-portable', 'events.csv', str(source), source.stat().st_size)
    restored_root = tmp_path / 'restored-raw'
    restored = restored_root / 'pilot-a/assessment-portable/events.csv'
    restored.parent.mkdir(parents=True); restored.write_bytes(source.read_bytes())
    monkeypatch.setattr(store, '_RAW_ROOT', str(restored_root))
    assert store.raw_files_for('assessment-portable') == [(str(restored), 'events.csv')]
    # The original still exists: recovery must never depend on it.
    restored.write_bytes(b'user\nmallory\n')
    with pytest.raises(ValueError, match='missing_or_changed'):
        store.raw_files_for('assessment-portable')


def test_recovery_rejects_partial_captures_instead_of_dropping_files(ingest_store, monkeypatch):
    from src.core.ingest import assessment_worker as worker
    store = ingest_store
    store.create_job('assessment-partial', org='pilot-a')
    directory = Path(store.raw_dir_for('assessment-partial', tenant_id='pilot-a'))
    for name in ('first.csv', 'second.csv'):
        source = directory / name; source.write_bytes(b'user\nalice\n')
        store.register_file('assessment-partial', name, str(source), source.stat().st_size)
    source.unlink()
    monkeypatch.setattr(worker, '_ACTIVE_JOB_IDS', set())
    monkeypatch.setattr(worker, 'enqueue_job', lambda *args: pytest.fail('partial input was queued'))
    assert worker._recover_queued_jobs() == 0
    assert store.get_job('assessment-partial')['status'] == 'failed'


def test_recovery_discards_only_interrupted_derived_rows(ingest_store):
    store = ingest_store
    store.create_job('interrupted', org='pilot-a')
    store.create_job('completed', org='pilot-a')
    for aid in ('interrupted', 'completed'):
        store.persist_row_batch(aid, [{'row_index': 0, 'user': 'alice'}])
    store.update_job('completed', status='ready')
    store.reset_incomplete_job('interrupted')
    rows = store._db().execute('SELECT assessment_id, count(*) FROM normalized_rows GROUP BY assessment_id').fetchall()
    assert rows == [('completed', 1)]
    with pytest.raises(ValueError, match='only_incomplete'):
        store.reset_incomplete_job('completed')
    assert store._db().execute('SELECT count(*) FROM normalized_rows').fetchone()[0] == 1


def test_recovery_backlog_waits_for_capacity_without_claiming_new_uploads(ingest_store, monkeypatch):
    from src.core.ingest import assessment_worker as worker
    store = ingest_store
    monkeypatch.setattr(worker, '_INGEST_QUEUE', asyncio.Queue(maxsize=2))
    monkeypatch.setattr(worker, '_ACTIVE_JOB_IDS', set())
    monkeypatch.setattr(worker, '_RECOVERY_PENDING_IDS', set())
    for index in range(3):
        aid = f'recovery-{index}'
        store.create_job(aid, org='pilot-a')
        directory = Path(store.raw_dir_for(aid, tenant_id='pilot-a'))
        capture = directory / 'events.csv'; capture.write_bytes(b'user\nalice\n')
        store.register_file(aid, 'events.csv', str(capture), capture.stat().st_size)
        store.persist_row_batch(aid, [{'row_index': 0, 'user': 'alice'}])
    assert worker._recover_queued_jobs() == 2
    pending = next(iter(worker._RECOVERY_PENDING_IDS))
    assert store.get_job(pending)['status'] == 'queued'
    assert store._db().execute('SELECT count(*) FROM normalized_rows WHERE assessment_id=?', [pending]).fetchone()[0] == 1
    # A new HTTP upload may have a job row before its captures are registered.
    store.create_job('new-upload-still-writing', org='pilot-a')
    worker._INGEST_QUEUE.get_nowait(); worker._INGEST_QUEUE.task_done()
    assert worker._recover_queued_jobs(pending_only=True) == 1
    assert not worker._RECOVERY_PENDING_IDS
    assert pending in worker._ACTIVE_JOB_IDS
    assert store.get_job('new-upload-still-writing')['status'] == 'queued'
    assert all(store.get_job(f'recovery-{i}')['status'] == 'queued' for i in range(3))


def test_evidence_order_is_stable_for_equal_scores(ingest_store):
    store = ingest_store
    store.create_job('equal-scores', org='pilot-a')
    store.persist_row_batch('equal-scores', [{'row_index': i, 'triage_score': 0.5} for i in (5, 2, 4)])
    assert [row['row_index'] for row in store.load_rows('equal-scores')] == [2, 4, 5]


def test_interrupted_restore_cannot_be_served(stored, tmp_path, monkeypatch):
    root, key, archive = stored
    backup(root, archive, key)
    target = tmp_path / 'interrupted-restore'
    real_open = Path.open
    def fail_output(path, mode='r', *args, **kwargs):
        if mode == 'xb' and path.name == 'evidence.bin':
            raise OSError('simulated full disk')
        return real_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fail_output)
    with pytest.raises(OSError):
        restore(archive, target, key)
    with pytest.raises(RuntimeError, match='incomplete_restore'):
        with state_lock(target):
            pytest.fail('partial restore was allowed to start')
