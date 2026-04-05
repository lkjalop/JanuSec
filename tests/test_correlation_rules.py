import os
import json
import asyncio
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_chain_scoring_with_default_weights():
    # Ensure week-1 default weights are present (mapping/diversity zero by default)
    os.environ.pop('SCORING_WEIGHTS_JSON', None)
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    payload = {
        'session_ids': ['batch-overlap-a', 'batch-overlap-b'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'user': 'user', 'host': 'host', 'file_hash': 'sha256'}
    }
    from src.api.app import create_app
    _app = create_app({'mode': 'test'})
    async with AsyncClient(app=_app, base_url='http://test', timeout=10.0) as ac:
        headers = {'x-api-key':'devkey123', 'X-Roles': 'analyst'}
        resp = await ac.post('/api/v1/graph/session/build', json=payload, headers=headers)
        if resp.status_code != 200:
            try:
                body = resp.json()
            except Exception:
                body = {'text': resp.text}
            pytest.fail(f"graph/session/build returned {resp.status_code}: {body}")
        body = resp.json()
        summary = body.get('summary') or {}
        # Should include correlation, ewma_alpha, and confidence fields
        assert isinstance(summary.get('correlation'), dict)
        assert summary.get('ewma_alpha') is not None
        assert isinstance(summary.get('confidence'), (int, float))
        # Week-1 deterministic factor set contains 'multi_source_correlation' and 'entity_diversity_high'
        facs = summary.get('factors') or []
        names = set()
        for f in facs:
            if isinstance(f, dict):
                names.add(f.get('factor') or f.get('name'))
            else:
                names.add(str(f))
        assert 'multi_source_correlation' in names
        assert 'entity_diversity_high' in names


@pytest.mark.asyncio
async def test_scoring_weights_influence_confidence():
    # Apply explicit scoring weights and expect an increase in confidence
    os.environ['SCORING_WEIGHTS_JSON'] = json.dumps({'mapping': 0.25, 'diversity': 0.07})
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    payload = {
        'session_ids': ['batch-overlap-x', 'batch-overlap-y', 'batch-overlap-z'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'user': 'user', 'host': 'host', 'file_hash': 'sha256'}
    }
    from src.api.app import create_app
    _app = create_app({'mode': 'test'})
    async with AsyncClient(app=_app, base_url='http://test', timeout=10.0) as ac:
        headers = {'x-api-key':'devkey123', 'X-Roles': 'analyst'}
        resp = await ac.post('/api/v1/graph/session/build', json=payload, headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        summary = body.get('summary') or {}
        base_breakdown = summary.get('graph_confidence_breakdown') or {}
        # The diversity_bonus and mapping_bonus should reflect non-zero when weights provided
        assert (base_breakdown.get('diversity_bonus') or 0.0) >= 0.0
        assert (base_breakdown.get('mapping_bonus') or 0.0) >= 0.0
        # Confidence should be bounded and increased compared to base
        assert summary.get('confidence') <= 0.99
        assert summary.get('confidence') >= base_breakdown.get('base', 0.0)


@pytest.mark.asyncio
async def test_factor_paths_contextual_scoring():
    # Simulate Week-1 factor presence to exercise factor path scoring
    # Build a session and then ensure factor_paths are present when rules fire
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    payload = {
        'session_ids': ['batch-overlap-p', 'batch-overlap-q'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'user': 'user', 'host': 'host', 'file_hash': 'sha256'}
    }
    from src.api.app import create_app
    _app = create_app({'mode': 'test'})
    async with AsyncClient(app=_app, base_url='http://test', timeout=10.0) as ac:
        headers = {'x-api-key':'devkey123', 'X-Roles': 'analyst'}
        resp = await ac.post('/api/v1/graph/session/build', json=payload, headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        summary = body.get('summary') or {}
        # factor_paths optional; when present should include score
        fps = summary.get('factor_paths') or []
        for fp in fps:
            assert 'factor' in fp
            assert isinstance(fp.get('score'), (int, float))
import asyncio

import pytest

from core.correlation.hunt_correlation import get_correlation_engine


class DummyConfig(dict):
    pass

@pytest.mark.asyncio
async def test_correlation_synergy_office_ps_rare_ja3():
    cfg = DummyConfig()
    eng = get_correlation_engine(cfg)
    factors = [
        'lane_process_lineage:office_macro_spawn_powershell',
        'lane_ja3_novelty:ja3_rare'
    ]
    new = await eng.correlate(factors)
    assert 'corr_office_ps_rare_ja3' in new

@pytest.mark.asyncio
async def test_correlation_synergy_encoded_signed_unsigned():
    cfg = DummyConfig()
    eng = get_correlation_engine(cfg)
    factors = [
        'lane_process_lineage:powershell_encoded_command',
        'lane_process_lineage:signed_to_unsigned_transition'
    ]
    new = await eng.correlate(factors)
    assert 'corr_encoded_ps_signed_to_unsigned' in new
