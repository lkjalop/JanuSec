import asyncio
import pytest


async def _call_persist(monkeypatch, tmp_path):
    # Create a fake mixin instance
    from src.orchestrator.persistence import DecisionPersistenceMixin

    class Dummy(DecisionPersistenceMixin):
        def __init__(self):
            self.config = type('C', (), {'get_current_digests': lambda s: {}})()
            self.logger = type('L', (), {'debug': lambda *a, **k: None})()

        async def _append_audit_chain(self, *args, **kwargs):
            return None

        async def _persist_factor_embeddings(self, *args, **kwargs):
            return None

    # Stub ab_test_repo.list_active to return a test
    async def fake_list_active():
        return [{'id': 'test-1'}]

    called = {'assign': False}

    async def fake_assign_if_enabled(test_id, subject_id, tenant_id=None):
        called['assign'] = True
        return 'B'

    # Apply monkeypatches: list_active used by persistence assign loop
    import src.repositories.ab_test_repo as ab_repo
    monkeypatch.setattr(ab_repo, 'list_active', fake_list_active)
    # Monkeypatch shadow_runner.assign_if_enabled directly so the scheduler calls our stub
    import src.core.ab.shadow_runner as sr
    monkeypatch.setattr(sr, 'assign_if_enabled', fake_assign_if_enabled)

    d = Dummy()
    event = {'id': 'evt-1', 'tenant_id': 't1'}
    class R: verdict = 'allow'; confidence = 0.5; factors = []
    await d._persist_decision(event, R())
    return called['assign']


def test_persist_triggers_ab_assign(monkeypatch, tmp_path):
    res = asyncio.get_event_loop().run_until_complete(_call_persist(monkeypatch, tmp_path))
    assert res is True
