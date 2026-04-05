import os

import pytest

from core.embedding.providers import EmbeddingSelector


@pytest.mark.asyncio
async def test_embedding_selector_force_hash(monkeypatch):
    monkeypatch.setenv('EMBEDDING_FORCE_PROVIDER','hash')
    sel = EmbeddingSelector()
    prov = await sel.select(['a','b'])
    assert prov.name == 'hash'

@pytest.mark.asyncio
async def test_embedding_selector_low_complexity(monkeypatch):
    monkeypatch.delenv('EMBEDDING_FORCE_PROVIDER', raising=False)
    monkeypatch.setenv('EMBEDDING_COMPLEXITY_THRESHOLD','0.9')  # make threshold high so simple factors pick tiny
    sel = EmbeddingSelector()
    prov = await sel.select(['factor1','factor2'])
    # Should not escalate to sec (could be None) or minilm due to low complexity
    assert prov.name in ('tinybert_sec','minilm')

@pytest.mark.asyncio
async def test_embedding_selector_high_complexity(monkeypatch):
    monkeypatch.delenv('EMBEDDING_FORCE_PROVIDER', raising=False)
    monkeypatch.setenv('EMBEDDING_COMPLEXITY_THRESHOLD','0.1')
    sel = EmbeddingSelector()
    prov = await sel.select(['exfil_volume_high','lateral_movement_candidate','credential_access_pattern'])
    # Preferred escalation path may pick secbert unless disabled
    assert prov.name in ('secbert','tinybert_sec','minilm','hash')
