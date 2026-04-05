import pytest
from unittest import mock
from src.pipeline.runner import run_once
from src.pipeline.embedding_worker import process_batch
from src.api.integrations_endpoints import save_integration_config


def test_runner_no_collectors(monkeypatch):
    # Mock collectors to return empty lists
    monkeypatch.setattr('src.pipeline.runner.OktaIAMCollector.fetch_events', lambda self, x: [])
    monkeypatch.setattr('src.pipeline.runner.APIGatewayCollector.fetch_events', lambda self, x: [])
    # Mock DB connection to avoid real DB calls
    with mock.patch('src.pipeline.runner._get_conn') as mget:
        m = mock.MagicMock()
        m.cursor.return_value.__enter__.return_value.fetchall.return_value = []
        mget.return_value = m
        # Should run without exception
        run_once()


def test_embedding_worker_empty_queue(monkeypatch):
    # Mock DB to return no rows
    with mock.patch('src.pipeline.embedding_worker._get_conn') as mg:
        m = mock.MagicMock()
        cur = m.cursor.return_value.__enter__.return_value
        cur.fetchall.return_value = []
        mg.return_value = m
        process_batch(5)


def test_save_integration_config(monkeypatch):
    # Mock DB
    with mock.patch('src.api.integrations_endpoints._get_conn') as mg:
        m = mock.MagicMock()
        mg.return_value = m
        res = save_integration_config('postgres', {'tenant_id':'t1','config':{'dsn':'x'}})
        assert res.get('saved')
