import asyncio
import os
import types
import importlib

from fastapi import FastAPI
from fastapi.testclient import TestClient


class DummySched:
    def __init__(self):
        self._jobs = [{'key': 'j1', 'data': {'payload': '{}', 'interval': '60', 'next_run': '0'}}]

    async def list_jobs(self):
        return self._jobs


def test_admin_jobs_prefers_redis(monkeypatch):
    # Monkeypatch get_global_scheduler to return our DummySched
    async def _get():
        return DummySched()

    monkeypatch.setenv('ENABLE_REDIS_SCHEDULER', '1')
    # import module and monkeypatch at attribute level
    rs_mod = importlib.import_module('src.enrichment.redis_scheduler')
    monkeypatch.setattr(rs_mod, 'get_global_scheduler', _get, raising=False)

    app = FastAPI()
    crq = importlib.import_module('src.api.crq_observations_endpoints')
    jobs = importlib.import_module('src.api.admin_enrichment_scheduler')
    app.include_router(crq.router)
    app.include_router(jobs.router)
    client = TestClient(app)

    resp = client.get('/api/v1/admin/enrichment/jobs')
    assert resp.status_code == 200
    body = resp.json()
    assert body.get('source') == 'redis'
    assert isinstance(body.get('jobs'), list)
