from src.core.evidence_contract.projection_builder import build_typed_projection
from src.core.evidence_contract.path_validation import validate_investigation_paths
from src.core.evidence_contract.signed_snapshots import sign_snapshot


def test_projection_uses_actor_id_and_host_scoped_process_lineage():
    rows = [{
        "source_type": "sysmon", "EventID": 1, "Computer": "db-01",
        "user": "ACME\\james", "Image": "powershell.exe", "ProcessId": "42",
        "ParentImage": "cmd.exe", "ParentProcessId": "41",
        "DestinationIp": "203.0.113.8", "timestamp": "2026-08-19T01:00:00Z",
    }]
    nodes, edges, _ = build_typed_projection(
        tenant_id="t1", case_id="c1", rows=rows, ledger_head_hash="a" * 64,
    )
    kinds = {node["kind"] for node in nodes}
    bases = {basis for edge in edges for basis in edge["match_basis"]}
    assert {"principal", "asset", "process", "address"} <= kinds
    assert "process_parentage" in bases
    assert "process_network_connection" in bases


def test_denied_cloud_read_does_not_create_interaction():
    rows = [{
        "source_type": "alibaba", "eventName": "GetObject",
        "userIdentity": {"principalId": "ram-user"}, "object_key": "secret.txt",
        "errorCode": "AccessDenied", "timestamp": "2026-08-19T01:00:00Z",
    }]
    _, edges, _ = build_typed_projection(
        tenant_id="t1", case_id="c1", rows=rows, ledger_head_hash="a" * 64,
    )
    assert not any(edge["edge_type"] == "observed_interaction" for edge in edges)


def test_projection_preserves_roles_and_gcp_delegation_for_iam_validation(monkeypatch):
    nodes, edges, _ = build_typed_projection(
        tenant_id="t1", case_id="c1", ledger_head_hash="c" * 64,
        rows=[{
            "source_type": "gcp", "timestamp": "2026-08-19T01:00:00Z",
            "protoPayload": {
                "authenticationInfo": {
                    "principalEmail": "runtime@project.iam.gserviceaccount.com",
                    "serviceAccountDelegationInfo": [{
                        "firstPartyPrincipal": {"principalEmail": "builder@example.com"},
                    }],
                },
                "resourceName": "projects/p/secrets/db", "methodName": "AccessSecretVersion",
            },
        }],
    )
    assert any("actor" in node["roles"] for node in nodes if node["kind"] == "principal")
    assert any(
        edge["edge_type"] == "configured_exposure"
        and "observed_service_account_delegation" in edge["match_basis"]
        for edge in edges
    )
    delegation = next(edge for edge in edges if "observed_service_account_delegation" in edge["match_basis"])
    iam = sign_snapshot(
        kind="iam", tenant_id="t1",
        payload={"allowed_paths": [["builder@example.com", "runtime@project.iam.gserviceaccount.com"]]},
        source="gcp-iam", version="1", valid_from="2026-08-01T00:00:00Z",
        valid_to="2026-12-20T00:00:00Z", key="secret",
    )
    monkeypatch.setenv("JANUSEC_SNAPSHOT_HMAC_KEY", "secret")
    result = validate_investigation_paths(
        [delegation], records_by_id={delegation["evidence_ids"][0]: {"occurred_at": "2026-08-19T01:00:00Z"}},
        authorization_snapshot=iam,
    )
    assert result["validated_edges"]
