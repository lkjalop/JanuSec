import os
import asyncio
import pytest
from src.api.deep_analyze_endpoints import LLMSummaryStage


pytestmark = pytest.mark.skipif(os.getenv('RUN_OLLAMA_TESTS','0') != '1', reason='Ollama tests disabled')


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_ollama_llm_summary_runs():
    stage = LLMSummaryStage()
    ctx = {'rows': [], 'options': {'auto_llm': True}}
    res = run(stage.run(ctx))
    assert res['status'] == 'done'
    assert 'llm_summary' in res['result']
