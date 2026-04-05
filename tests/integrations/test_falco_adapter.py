import pytest

from src.integrations.falco_adapter import FalcoAdapter


@pytest.mark.asyncio
async def test_falco_enrichment_with_sbom_lookup():
    f = FalcoAdapter()
    await f.connect()
    events, cursor = await f.fetch_since()
    assert len(events) == 2
    assert cursor is not None
    e0 = events[0]
    assert "vulns" in e0 and isinstance(e0["vulns"], list)
    assert e0["process"].startswith("falco_target")
    # KEV/EPSS keys may be present when enrichment utils exist
    if "kev" in e0:
        assert isinstance(e0["kev"], dict)
    if "epss" in e0:
        assert isinstance(e0["epss"], dict)
