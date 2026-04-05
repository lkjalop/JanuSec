import asyncio

from src.api.graph_sessions import preview_score


def test_preview_score_direct_call():
    payload = {
        'path': [
            {'user': 'Alice', 'file_hash': 'abc123'},
            {'domain': 'example.com', 'nxdomain_rate': 0.5}
        ],
        'weights': None
    }
    # preview_score is async
    res = asyncio.get_event_loop().run_until_complete(preview_score(payload))
    assert 'score' in res
    assert isinstance(res['score'], float)
    assert 'contributions' in res
