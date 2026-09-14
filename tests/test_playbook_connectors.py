import asyncio

from src.soar.runner import PlaybookRunner
from src.soar.connectors import get_registry


def test_runner_uses_connectors(monkeypatch):
    called = {}

    async def fake_idp(params):
        called['idp'] = params
        return {'revoked': True}

    async def fake_fw(params):
        called['fw'] = params
        return {'blocked': True}

    reg = get_registry()
    # patch registry entries
    monkeypatch.setattr(reg, '_connectors', {**reg._connectors, 'idp.revoke_sessions': fake_idp, 'firewall.block_ip': fake_fw})

    playbook = {
        'name': 'test-connectors',
        'dry_run': False,
        'steps': [
            {'type': 'revoke_sessions', 'params': {'user': 'alice', 'connector': 'idp.revoke_sessions'}},
            {'type': 'block_ip', 'params': {'ip': '1.2.3.4', 'connector': 'firewall.block_ip'}},
        ]
    }

    runner = PlaybookRunner(dry_run=False)
    out = asyncio.get_event_loop().run_until_complete(runner.run(playbook))
    assert out['playbook'] == 'test-connectors'
    assert any(r['name'] == 'revoke_sessions' and r['ok'] for r in out['results'])
    assert any(r['name'] == 'block_ip' and r['ok'] for r in out['results'])
    assert 'idp' in called and called['idp']['user'] == 'alice'
    assert 'fw' in called and called['fw']['ip'] == '1.2.3.4'
