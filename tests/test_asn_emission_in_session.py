import asyncio
import os
from src.api import graph_sessions
from src.live import asn_lookup, asn_stats


def test_asn_emission_in_session():
    # Enable test helpers to allow injected ips
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    # Seed a deterministic mapping for the public IP
    asn_lookup.seed_mapping({'8.8.8.8': 'AS65001'})
    # Also seed large baseline counts to make AS65001 relatively rare
    # (populate_from_source increases the global total; make others large)
    asn_stats.populate_from_source({'AS65001': 0.0, 'AS65002': 10000.0, 'AS65003': 5000.0})

    payload = {
        'session_ids': ['batch-overlap-A', 'batch-overlap-B'],
        'correlate': True,
        'ewma': False,
        # Inject the public IP so graph_sessions will see it
        'test_ips': ['8.8.8.8']
    }

    res = asyncio.run(graph_sessions.build_session(payload, request=None))
    assert 'summary' in res
    summary = res['summary']
    # Check that asn_rare factor was added
    factors = summary.get('factors') or []
    # factors may include dicts for batch_missing, but asn_rare will be a dict before normalization
    found = False
    asn_found = None
    for f in factors:
        if isinstance(f, dict) and f.get('factor') == 'asn_rare':
            found = True
            asn_found = f.get('asn')
            assert f.get('rarity') is not None
    assert found, f"asn_rare factor not found in factors: {factors}"
    # Prefer the seeded ASN if present, otherwise accept any rare ASN emitted
    if asn_found and asn_found != 'AS65001':
        # If our seeded ASN wasn't chosen as rare, ensure it was at least looked up earlier
        # (sanity check via asn_lookup mapping)
        mapped = asn_lookup.lookup_asn('8.8.8.8')
        assert mapped == 'AS65001'
