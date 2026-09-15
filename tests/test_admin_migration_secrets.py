from types import SimpleNamespace
from src.api import admin_migrations


def test_migration_uses_argument_vector_and_redacts_credentials(monkeypatch):
    dsn = 'postgresql://operator:synthetic-secret@localhost/testdb'
    monkeypatch.setenv('ADMIN_TRIGGER_MIGRATIONS', '1')
    monkeypatch.setenv('APP_DB_DSN', dsn)
    monkeypatch.setattr(admin_migrations, 'psycopg2', None)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=dsn+' synthetic-secret', stderr='')

    monkeypatch.setattr(admin_migrations.subprocess, 'run', run)
    result = admin_migrations.trigger_migrations({'confirm': True}, user={'sub': 'operator'})
    argv, options = calls[0]
    assert isinstance(argv, list) and options['shell'] is False
    assert dsn not in argv and options['env']['APP_DB_DSN'] == dsn
    assert 'synthetic-secret' not in result['output'] and dsn not in result['output']


def test_role_header_cannot_authorize_migration(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    monkeypatch.setenv('ADMIN_TRIGGER_MIGRATIONS', '1')
    app = FastAPI()
    app.include_router(admin_migrations.router)
    response = TestClient(app).post('/api/v1/admin/db/migrate',
                                    headers={'x-roles': 'admin'}, json={'confirm': True})
    assert response.status_code == 401
