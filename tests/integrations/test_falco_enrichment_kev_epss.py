import pytest

from src.integrations.falco_adapter import FalcoAdapter


@pytest.mark.asyncio
async def test_falco_kev_epss_structure_if_available():
    try:
        # Verify enrichment functions exist before asserting structure
        from src.integrations.vuln_enrichment import kev_lookup, epss_lookup  # type: ignore
    except Exception:
        pytest.skip("vuln_enrichment not available; skipping KEV/EPSS structure assertions")

    f = FalcoAdapter()
    await f.connect()
    events, _ = await f.fetch_since()
    e0 = events[0]
    assert "kev" in e0 and isinstance(e0["kev"], dict)
    assert "epss" in e0 and isinstance(e0["epss"], dict)
    # Check expected keys when provided by enrichment path
    # These are representative and may vary based on implementation
    kev = e0["kev"]
    epss = e0["epss"]
    # Use permissive checks: presence of common fields
    assert ("score" in kev) or ("advisory" in kev) or ("entries" in kev)
    assert ("probability" in epss) or ("score" in epss) or ("entries" in epss)
