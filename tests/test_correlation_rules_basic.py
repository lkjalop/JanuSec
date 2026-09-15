from src.core.correlation.hunt_correlation import create_correlation_engine

class Cfg:
    correlation_window_seconds = 300


def test_correlation_new_rules_minimal():
    eng = create_correlation_engine(Cfg())
    # Seed: beacon + header injection
    out = __import__('asyncio').get_event_loop().run_until_complete(
        eng.correlate(['net:beacon_periodic','http:header_injection_pattern'], event={'host':'h1'})
    )
    assert any('corr_header_injection_beacon' == x for x in out)
    # JA3 rare + new domain
    out = __import__('asyncio').get_event_loop().run_until_complete(
        eng.correlate(['ssl:ja3_rare','domain_novel_observed'], event={'host':'h1'})
    )
    assert 'corr_ja3_rare_new_domain' in out
    # Port scatter + JARM rare
    out = __import__('asyncio').get_event_loop().run_until_complete(
        eng.correlate(['net:egress_port_scatter','ssl:jarm_rare'], event={'host':'h1'})
    )
    assert 'corr_port_scatter_jarm_rare' in out
