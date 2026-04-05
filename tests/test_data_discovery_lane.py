from __future__ import annotations

import asyncio

from src.core.hunt.lanes.data_discovery import LANE
from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.hopgraph_queue import peek, drain


def test_data_discovery_emits_enumeration_and_sensitive_listing(monkeypatch):
    evt = {'path_list': [f'/tmp/file{i}.txt' for i in range(12)], 'search': ''}
    env = EvidenceEnvelope(event=evt)
    # run lane
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 5})()))
    # verify envelope emissions
    assert env.emissions
    names = [e for e in env.all_factors]
    assert 'data:automated_file_enumeration' in names


def test_data_discovery_detects_schema_and_search_keywords(monkeypatch):
    evt = {'query': 'SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=\'public\'', 'query_text': 'find ssn records'}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 3})()))
    names = [e for e in env.all_factors]
    assert 'data:database_schema_enumeration' in names
    assert 'data:search_keyword_sensitive' in names
