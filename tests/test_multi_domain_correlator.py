import time

import pytest

from src.core.correlation.multi_domain_chains import (
    DomainEvent,
    MultiDomainCorrelator,
    SecurityDomain,
)


class _HopGraphStub:
    def __init__(self):
        self.snapshots = 0
        self.last_start = None

    def snapshot(self, limit: int = 50):
        self.snapshots += 1
        return {"limit": limit, "snapshots": self.snapshots}

    def explain_chain(self, start: str, **_):
        self.last_start = start
        return {
            "start": start,
            "chains": [
                {"score": 0.9, "nodes": [f"{start}", "process:alpha", "domain:evil.com"], "length": 3}
            ]
        }


def _event(
    domain: SecurityDomain,
    minutes_ago: float = 0.0,
    user: str = "user",
    host: str = "host",
    *,
    factors: list[str] | None = None,
    score: float = 0.5,
):
    ts = time.time() - minutes_ago * 60.0
    return DomainEvent(
        domain=domain,
        event_id=f"{domain.value}-{minutes_ago}",
        timestamp=ts,
        factors=factors or [domain.value],
        entities={"user": user, "host": host},
        score=score,
    )


def test_multi_domain_chain_emitted_with_recommendations():
    hopgraph = _HopGraphStub()
    correlator = MultiDomainCorrelator(hopgraph_client=hopgraph, ttl_seconds=600)
    ev1 = _event(SecurityDomain.ENDPOINT)
    ev2 = _event(SecurityDomain.NETWORK, minutes_ago=1)

    correlator.process_event(ev1)
    chain = correlator.process_event(ev2)

    assert chain is not None
    assert set(chain.domains_involved) == {SecurityDomain.ENDPOINT, SecurityDomain.NETWORK}
    assert chain.recommendations[0].startswith("Escalate")
    assert chain.hopgraph_snapshot is not None
    assert chain.hopgraph_context is not None
    assert chain.recommendation_catalog
    assert chain.expires_at > chain.generated_at
    assert abs(chain.expires_at - chain.generated_at - 600) < 5  # ttl seconds


def test_ttl_enforced_and_chain_not_emitted():
    correlator = MultiDomainCorrelator(ttl_seconds=60)
    old_event = _event(SecurityDomain.ENDPOINT, minutes_ago=5)
    recent_event = _event(SecurityDomain.NETWORK, minutes_ago=0)

    correlator.process_event(old_event)
    chain = correlator.process_event(recent_event)

    assert chain is None


def test_recommendation_overrides():
    overrides = {"endpoint": ["custom endpoint action"]}
    correlator = MultiDomainCorrelator(recommendation_overrides=overrides)
    correlator.process_event(_event(SecurityDomain.ENDPOINT))
    chain = correlator.process_event(_event(SecurityDomain.IDENTITY, minutes_ago=0.5))
    assert chain is not None
    assert "custom endpoint action" in chain.recommendations
    assert any(rec for rec in chain.recommendation_catalog if rec['action'] == "custom endpoint action")


def test_chain_includes_factor_synthesis_summary():
    correlator = MultiDomainCorrelator(ttl_seconds=600)
    ev1 = _event(
        SecurityDomain.ENDPOINT,
        factors=['endpoint:vss_deletion'],
        score=0.8,
    )
    ev2 = _event(
        SecurityDomain.NETWORK,
        minutes_ago=0.2,
        factors=['net:beacon_periodic'],
        score=0.7,
    )
    correlator.process_event(ev1)
    chain = correlator.process_event(ev2)
    assert chain is not None
    assert chain.synthesis is not None
    assert chain.synthesis['final_score'] >= 0
    assert chain.total_score == pytest.approx(round(chain.synthesis['final_score'], 4))
    assert chain.confidence == pytest.approx(round(chain.synthesis['confidence'], 4))
    assert chain.raw_total_score == pytest.approx(round(ev1.score + ev2.score, 4))
