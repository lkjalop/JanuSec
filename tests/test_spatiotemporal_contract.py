from __future__ import annotations

import pytest

from src.core.evidence_contract.correlation import EdgeType
from src.core.evidence_contract.spatiotemporal import RoleAssertion, allowed_edge_types, validate_tenant_graph


def test_query_purpose_keeps_candidate_matches_out_of_causal_view() -> None:
    assert allowed_edge_types("causal_reconstruction") == frozenset({EdgeType.OBSERVED_CAUSAL})
    assert EdgeType.CANDIDATE_MATCH not in allowed_edge_types("causal_reconstruction")


def test_graph_rejects_cross_tenant_nodes() -> None:
    with pytest.raises(ValueError, match="cross_tenant"):
        validate_tenant_graph(
            [
                {"node_id": "a", "tenant_id": "acme", "kind": "principal"},
                {"node_id": "b", "tenant_id": "other", "kind": "asset"},
            ],
            [],
            tenant_id="acme",
        )


def test_observed_role_requires_evidence_but_inferred_role_can_express_uncertainty() -> None:
    with pytest.raises(ValueError, match="observed_role_requires_evidence"):
        RoleAssertion.from_dict(
            {"entity_id": "svc_sql", "role": "target", "status": "observed", "case_id": "c1", "tenant_id": "acme"}
        )
    assertion = RoleAssertion.from_dict(
        {"entity_id": "db01", "role": "victim", "status": "inferred", "case_id": "c1", "tenant_id": "acme"}
    )
    assert assertion.role.value == "victim"
