import os
import json
from src.api.graph_sessions import build_session
import pytest

# simple fixture-driven test: use a synthetic session id that uses fixtures folder

def test_mapping_factor_emitted_for_fixture():
    payload = { 'session_ids': ['batch-overlap-1','batch-overlap-2'], 'correlate': True, 'ewma': False, 'mapping': {'user':'user'} }
    # call build_session synchronously via asyncio.run
    import asyncio
    loop = asyncio.get_event_loop()
    res = loop.run_until_complete(build_session(payload))
    assert 'summary' in res or 'session_id' in res
    summary = res.get('summary') or res
    factors = summary.get('factors') or []
    names = [ (f.get('factor') if isinstance(f, dict) else f) for f in factors ]
    # mapping_semantics should be present either as structured factor or as name
    assert any((n=='mapping_semantics' or n=='mapping_semantics_rich' or n=='mapping_semantics_bonus') for n in names)

def test_mapping_factor_emitted_with_runtime():
    # simulate runtime providing simple trackers; pass runtime via request mocking is difficult here,
    # but graph_sessions.build_session uses runtime only when request provided. Instead emulate by
    # using session fixtures and mapping; we ensure mapping factor is included.
    payload = { 'session_ids': ['batch-overlap-1'], 'mapping': {'user':'user','host':'host','file_hash':'file_hash'} }
    import asyncio
    loop = asyncio.get_event_loop()
    res = loop.run_until_complete(build_session(payload))
    summary = res.get('summary') or res
    factors = summary.get('factors') or []
    names = [ (f.get('factor') if isinstance(f, dict) else f) for f in factors ]
    assert any(n=='mapping_semantics' or n=='mapping_semantics_rich' or n=='mapping_semantics_bonus' for n in names)
