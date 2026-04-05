import asyncio
import json

import pytest

try:
    import respx
    import httpx
except Exception:  # pragma: no cover
    respx = None

from src.integrations.sandbox.generic_provider import GenericSandboxProvider


@pytest.mark.asyncio
@pytest.mark.skipif(respx is None, reason='respx not installed')
async def test_generic_provider_submit_and_poll_with_retry(tmp_path):
    # create a fake integration config
    cfg = {
        'base_url': 'https://fake-sandbox.local',
        'submit_file_path': '/tasks/create/file',
        'report_path_template': '/tasks/report/{task_id}',
    }
    conf_path = tmp_path / 'data' / 'integrations'
    conf_path.mkdir(parents=True)
    (conf_path / 'fake.json').write_text(json.dumps(cfg))

    # monkeypatch loading path by setting data/integrations
    import os

    os.makedirs('data/integrations', exist_ok=True)
    with open('data/integrations/fake.json', 'w', encoding='utf8') as fh:
        json.dump(cfg, fh)

    provider = GenericSandboxProvider('fake', timeout=10, max_retries=3)

    with respx.mock(base_url='https://fake-sandbox.local') as rs:
        # submit endpoint returns task id
        rs.post('/tasks/create/file').mock(return_value=httpx.Response(200, json={'task_id': 'task-123'}))

        # first two polls return 429, then success
        poll = rs.get('/tasks/report/task-123')
        poll.side_effect = [
            httpx.Response(429, text='rate limit'),
            httpx.Response(429, text='rate limit'),
            httpx.Response(200, json={'report': {'status': 'completed', 'verdict': 'malicious'}}),
        ]

        # call submit (we can pass url as None and file bytes)
        task_id = await provider.submit(b'hello', 'test.txt', None)
        assert task_id == 'task-123'

        # call result - should retry on 429 and eventually return normalized
        res = await provider.result('task-123')
        assert isinstance(res, dict)
        assert res.get('verdict') in ('malicious', 'suspicious', 'benign')
