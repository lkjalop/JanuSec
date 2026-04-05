import os
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_week1_path_scoring_and_confidence_breakdown():
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    from src.api.app import create_app
    _app = create_app({'mode': 'test'})
    payload = {
        'session_ids': ['batch-overlap-a','batch-overlap-b'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'user':'user','host':'host','file_hash':'sha256'},
        # Simulate detectors presence indirectly via overlap; factor-path scoring hooks exist
    }
    async with AsyncClient(app=_app, base_url='http://test', timeout=10.0) as ac:
        headers = {'x-api-key':'devkey123','X-Roles':'analyst'}
        resp = await ac.post('/api/v1/graph/session/build', json=payload, headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Basic assertions on core scoring outputs
        # Confidence may be nested under summary; fallback accordingly
        summary = body.get('summary', {})
        confidence = body.get('confidence', summary.get('confidence'))
        verdict = body.get('verdict', summary.get('verdict'))
        assert isinstance(confidence, (int, float))
        assert verdict in {'escalate','watch','benign','SUSPECT','suspicious','malicious', None}
        # Factors should include mapping_semantics canonical factor object (non-fixture path)
        factors = body.get('factors') or summary.get('factors') or []
        assert any(isinstance(f, dict) and (f.get('factor')=='mapping_semantics') for f in factors)
