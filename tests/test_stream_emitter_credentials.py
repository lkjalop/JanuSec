import pytest
from src.connectors import stream_emitter


def test_no_implicit_demo_credential(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("JANUSEC_API_KEY", raising=False)
    assert stream_emitter._stream_cfg()[3] == ""


@pytest.mark.asyncio
async def test_missing_key_rejected_before_network(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("JANUSEC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="explicitly configured"):
        await stream_emitter.emit_to_stream([{"event": "synthetic"}], "test", assessment_id="test")
