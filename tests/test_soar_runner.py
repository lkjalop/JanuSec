import json
import os
from src.soar.runner import PlaybookRunner


def test_ioc_auto_block_dry_run():
    pb_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'playbooks', 'ioc_auto_block.json')
    pb_path = os.path.normpath(pb_path)
    with open(pb_path, 'r', encoding='utf-8') as f:
        pb = json.load(f)
    runner = PlaybookRunner(dry_run=True)
    res = runner.run(pb)
    # runner.run returns a coroutine; run it synchronously for test
    import asyncio
    out = asyncio.get_event_loop().run_until_complete(res)
    assert out['playbook'] == 'ioc-auto-block'
    assert out['dry_run'] is True
    # verify steps all returned ok
    assert len(out['results']) == 4
    for step in out['results']:
        assert 'ok' in step
        assert step['ok'] is True
