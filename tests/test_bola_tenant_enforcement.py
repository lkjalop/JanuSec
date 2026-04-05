import asyncio
import types
import pytest


@pytest.mark.asyncio
async def test_decisions_cross_tenant_write_block(monkeypatch):
    import src.repositories.decisions_repo as dr

    # Simulate existing row under tenant 'A'
    async def fake_fetchrow(sql, *args):
        return {'tenant_id': 'A'}

    async def fake_execute(sql, *args):
        return 'OK'

    monkeypatch.setattr(dr, 'fetchrow', fake_fetchrow, raising=False)
    monkeypatch.setattr(dr, 'execute', fake_execute, raising=False)
    monkeypatch.setattr(dr, 'with_retry', lambda fn: fn(), raising=False)

    class D:  # minimal decision object
        factors = []
        stage_timings = {}
        verdict = 'benign'
        confidence = 0.1
        processing_time_ms = 1.0
        custody_hash = None

    with pytest.raises(PermissionError):
        await dr.upsert_decision('evt-1', D(), tenant_id='B')


@pytest.mark.asyncio
async def test_events_cross_tenant_write_block(monkeypatch):
    import src.repositories.events_repo as er

    async def fake_fetchrow(sql, *args):
        return {'tenant_id': 'tenant-A'}

    async def fake_execute(sql, *args):
        return 'OK'

    monkeypatch.setattr(er, 'fetchrow', fake_fetchrow, raising=False)
    monkeypatch.setattr(er, 'execute', fake_execute, raising=False)
    monkeypatch.setattr(er, 'with_retry', lambda fn: fn(), raising=False)

    evt = {'id': 'e-1', 'source': 'test', 'event_type': 'proc', 'severity': 'low', 'timestamp': 0, 'details': {}}
    with pytest.raises(PermissionError):
        await er.upsert_event(evt, tenant_id='tenant-B')


@pytest.mark.asyncio
async def test_incidents_cross_tenant_write_and_read_block(monkeypatch):
    import src.repositories.incidents_repo as ir

    # Force in-memory path by removing DB fns
    monkeypatch.setattr(ir, 'execute', None, raising=False)
    monkeypatch.setattr(ir, 'with_retry', None, raising=False)

    # Upsert an incident under tenant X
    await ir.upsert_incident('inc-1', {'artifact_id': 'a1', 'title': 't', 'severity': 'high'}, tenant_id='tenant-X')
    # Cross-tenant read should not find it
    got = await ir.get_incident('inc-1', tenant_id='tenant-Y')
    assert got is None

