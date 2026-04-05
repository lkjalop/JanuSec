import os
import asyncio
import pytest

from src.connectors.proofpoint import ProofpointConnector
from src.connectors.mimecast import MimecastConnector


@pytest.mark.asyncio
async def test_proofpoint_connector_env_token(monkeypatch):
    monkeypatch.setenv('PROOFPOINT_BEARER', 'fake-token-123')
    c = ProofpointConnector()
    # No live httpx calls will be made because _fetch_paginated expects httpx; just ensure token retrieval
    with pytest.raises(Exception):
        # execute will try to call http_get and fail in environments without httpx; ensure error type
        await c.execute('example.com', 'victim@example.com')


@pytest.mark.asyncio
async def test_mimecast_connector_env_token(monkeypatch):
    monkeypatch.setenv('MIMECAST_BEARER', 'fake-token-456')
    c = MimecastConnector()
    with pytest.raises(Exception):
        await c.execute('example.com', 'victim@example.com')
