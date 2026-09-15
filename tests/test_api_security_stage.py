from __future__ import annotations

import logging
import types

import pytest

from core.event_pipeline.stages.api_security import api_security_stage
from core.event_pipeline.stages.base import StageContext


def _ctx() -> StageContext:
    return StageContext(
        registry=None,
        config=types.SimpleNamespace(),
        logger=logging.getLogger(__name__),
        state={'enrichment_cache': {}},
    )


@pytest.mark.asyncio
async def test_api_security_stage_flags_bola_and_pii():
    ctx = _ctx()
    event = {
        'event_type': 'api_request',
        'uri': '/api/v1/users/1234/payout',
        'method': 'GET',
        'auth_user': 'analyst@example',
        'body': {'user_id': '1234'},
        'response_body': 'customer ssn 123-45-6789 stored',
        'response_headers': {'Access-Control-Allow-Origin': '*'},
        'headers': {'host': 'orders.api.internal'},
        'status': 200,
    }
    result = await api_security_stage(event, ctx)
    assert 'api:bola_resource_mismatch' in result.factors
    assert 'api:data_exposure_pii' in result.factors
    assert 'api:cors_wildcard' in result.factors
    cache = ctx.state['enrichment_cache']['api_security']
    assert cache['alerts'], "alerts should be captured in enrichment cache"
    assert 'api_auth_context' in ctx.state['enrichment_cache']['missing_logs']


@pytest.mark.asyncio
async def test_api_security_stage_noop_for_non_api():
    ctx = _ctx()
    event = {'event_type': 'process_start', 'process_name': 'cmd.exe'}
    result = await api_security_stage(event, ctx)
    assert result.factors == []
    assert ctx.state['enrichment_cache'] == {}


@pytest.mark.asyncio
async def test_api_security_stage_detects_scenarios():
    ctx = _ctx()
    event = {
        'event_type': 'api_request',
        'uri': '/automation/runbook/encrypt',
        'method': 'POST',
        'auth_user': 'svc_rpa',
        'headers': {'host': 'automation.internal'},
        'file_count': 999,
        'latency_ms': 12000,
        'status': 503,
    }
    result = await api_security_stage(event, ctx)
    assert 'api:ransomware_api_activity' in result.factors
    assert 'api:automation_runbook_abuse' in result.factors
    assert result.metadata and 'api_security_timeline' in result.metadata
    cache = ctx.state['enrichment_cache']['api_security']
    assert cache['forensics'], "timeline entries should be cached"
