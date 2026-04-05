import asyncio
import os
import json
import pytest

from src.ml.online_trainer import generate_candidate_weights


@pytest.mark.asyncio
async def test_generate_candidate_weights_empty(tmp_path):
    # Ensure snapshot path directory exists
    os.makedirs('data', exist_ok=True)
    # No feedback in DB -> should return empty dict
    c = await generate_candidate_weights(window='1 day', tenant_id=None, max_delta=0.05)
    assert isinstance(c, dict)
