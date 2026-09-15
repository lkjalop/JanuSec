import asyncio
import os
import json
import time
import tempfile
from unittest import mock

import pytest

from src.outbox import async_consumer as ac  # type: ignore


@pytest.mark.asyncio
async def test_outbox_retry_and_dlq(tmp_path, monkeypatch):
    # prepare outbox file
    outpath = tmp_path / 'outbox.jsonl'
    ev1 = {'dataset_id':'ds','event_id':'e1'}
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write(json.dumps(ev1) + '\n')

    monkeypatch.setenv('OUTBOX_PATH', str(outpath))
    monkeypatch.setenv('OUTBOX_STATE_PATH', str(tmp_path / 'state.json'))
    monkeypatch.setenv('OUTBOX_DLQ_PATH', str(tmp_path / 'dlq.jsonl'))
    monkeypatch.setenv('OUTBOX_MAX_RETRIES','2')
    # ensure module-level constants updated for test
    ac.OUTBOX_PATH = str(outpath)
    ac.OUTBOX_STATE = str(tmp_path / 'state.json')
    ac.DLQ_PATH = str(tmp_path / 'dlq.jsonl')
    ac.MAX_RETRIES = 2
    ac.POLL_MS = 100
    # monkeypatch upsert_incident to fail then succeed
    calls = {'cnt':0}

    async def fake_upsert(ev):
        calls['cnt'] += 1
        if calls['cnt'] <= 2:
            raise Exception('boom')
        return {'ok':True}

    monkeypatch.setattr(ac, 'upsert_incident', lambda ev: fake_upsert(ev))

    stop = asyncio.Event()
    task = asyncio.create_task(ac.run_outbox(stop))
    # wait until DLQ appears or timeout
    dlq = tmp_path / 'dlq.jsonl'
    for _ in range(20):
        if dlq.exists():
            break
        await asyncio.sleep(0.3)
    stop.set()
    await task
    assert dlq.exists()
    lines = [l for l in dlq.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(lines) >= 1
