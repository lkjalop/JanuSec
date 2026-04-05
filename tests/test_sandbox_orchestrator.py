import asyncio
import os
import json
import time
from tempfile import TemporaryDirectory

from src.artifact.sandbox_submission import submit_artifact


def _read_lines(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return [json.loads(l) for l in fh]


def test_orchestrator_persists(tmp_path):
    # Override env paths
    submissions = tmp_path / 'subs.jsonl'
    results = tmp_path / 'res.jsonl'
    os.environ['SANDBOX_SUBMISSIONS_PATH'] = str(submissions)
    os.environ['SANDBOX_RESULTS_PATH'] = str(results)

    # Run submission (sim-mode because providers default to no base)
    loop = asyncio.get_event_loop()
    tid = loop.run_until_complete(submit_artifact('art-1', b'abc', 'a.bin', None, provider_name='cuckoo', meta={'note':'test'}))
    assert tid.startswith('sim-')

    # wait briefly for background task to write results
    time.sleep(0.2)

    subs = _read_lines(submissions)
    assert subs and subs[0]['artifact_id'] == 'art-1'

    # results file may contain None result entry
    res_lines = _read_lines(results)
    assert res_lines and res_lines[0]['artifact_id'] == 'art-1'
