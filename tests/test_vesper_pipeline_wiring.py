import os


def test_network_normalization_promotes_src_host_for_correlation():
    from src.pipeline.streaming_ingest import _normalize_network, normalize_row
    from src.core.ingest.assessment_worker import _normalize_ingest_row

    raw = {
        "src_host": "WS-MARTIN-01",
        "src_ip": "10.42.2.174",
        "dst_ip": "13.107.136.10",
        "domain": "martin-chen.sharepoint.com",
        "bytes": 250_000_000,
    }
    row = _normalize_network(raw)

    assert row["hostname"] == "WS-MARTIN-01"
    assert row["dst_host"] == "martin-chen.sharepoint.com"

    inferred = normalize_row(raw)
    assert inferred["_source_type"] == "network"
    assert inferred["hostname"] == "WS-MARTIN-01"

    ingest = _normalize_ingest_row(
        {
            "src_host": "WS-MARTIN-01",
            "domain": "martin-chen.sharepoint.com",
            "bytes": 250_000_000,
        },
        3,
    )
    assert ingest["source_type"] == "network"


def test_sharepoint_lookalike_marker_becomes_factor(monkeypatch):
    monkeypatch.setenv("JANUSEC_ORG_TENANT_NAME", "acmevesper")
    from src.core.ingest.assessment_worker import _collect_lane_factor_tags, _normalize_ingest_row

    row = _normalize_ingest_row(
        {
            "source_type": "network",
            "timestamp": "2026-04-28T10:00:00Z",
            "user": "martin.chen@acme-vesper.io",
            "resp_h": "martin-chen.sharepoint.com",
            "bytes": 250_000_000,
        },
        7,
    )

    assert row.get("_sharepoint_subdomain_mismatch") == "martin-chen"
    factors = _collect_lane_factor_tags([row])[7]
    assert "network:sharepoint_subdomain_mismatch" in factors


def test_cloud_phase4_accepts_vesper_oauth_and_cert_fields(monkeypatch):
    monkeypatch.setenv("ENABLE_IAM_FACTORS", "1")
    from src.core.detectors.iam_phase3_4 import detect_cloud_identity_phase4

    factors, _ = detect_cloud_identity_phase4(
        {
            "userPrincipalName": "martin.chen@acme-vesper.io",
            "appId": "f8a7c2e1-9b34-4e2d-b8f7-1a92c45e6d3a",
            "event_type": "OAuthConsentGrant",
            "scopes": "Mail.Read Files.Read.All User.Read.All offline_access",
            "app_verified": "false",
        }
    )
    assert "iam:oauth_consent_grant_suspicious_app" in factors

    factors, _ = detect_cloud_identity_phase4(
        {
            "userPrincipalName": "martin.chen@acme-vesper.io",
            "appId": "f8a7c2e1-9b34-4e2d-b8f7-1a92c45e6d3a",
            "event_type": "ServicePrincipalCertificateAdded",
        }
    )
    assert "iam:service_principal_credential_add" in factors


def test_svc_jenkins_rc4_is_suppressed_by_requester(monkeypatch):
    monkeypatch.setenv("ENABLE_IAM_FACTORS", "1")
    monkeypatch.setenv("KERBEROAST_EXCLUDE_SERVICES", "svc_jenkins")
    from src.core.detectors.iam_phase3_4 import detect_identity_phase3

    factors, _ = detect_identity_phase3(
        {
            "windows_event_id": "4769",
            "account_name": "svc_jenkins",
            "service_name": "host/SVR-JENKINS-01.acme-vesper.local",
            "ticket_encryption": "0x17",
        }
    )
    assert "iam:kerberoasting" not in factors


def test_cluster_narrator_prompt_includes_structured_signals():
    from src.core.ingest.cluster_narrator import _build_prompt

    prompt = _build_prompt(
        {
            "cluster_id": "vesper-1",
            "row_refs": [1],
            "shared_users": ["martin.chen"],
            "factor_tags": ["iam:golden_ticket", "exfil:cumulative_bytes_anomaly"],
            "_chrono_factors": ["recon:sustained_offhours_sequence"],
            "_ml_scores": {"martin.chen": {"cross_iso": 0.91, "ewma_residual": 2.4}},
            "compliance_violations": {"control_count": 2},
        },
        [{"row_index": 1, "timestamp": "2026-04-26T02:11:00Z", "user_canonical": "martin.chen"}],
    )

    assert "STRUCTURED SIGNALS FROM DETERMINISTIC PIPELINE" in prompt
    assert "iam:golden_ticket" in prompt
    assert "recon:sustained_offhours_sequence" in prompt
    assert "cross_iso" in prompt


def test_wmi_lateral_exec_factor_requires_remote_create():
    from src.core.ingest.assessment_worker import _collect_lane_factor_tags

    rows = [
        {
            "row_index": 1,
            "process_name": "wmic.exe",
            "command_line": "wmic /node:SVR-DB-01 process list",
        },
        {
            "row_index": 2,
            "process_name": "wmic.exe",
            "command_line": "wmic /node:SVR-APP-02 process call create powershell.exe -EncodedCommand AAA",
        },
    ]
    factors = _collect_lane_factor_tags(rows)
    assert "endpoint:wmi_lateral_exec" not in factors.get(1, [])
    assert "endpoint:wmi_lateral_exec" in factors[2]


def test_identity_graph_accepts_normalized_azure_user_fields(monkeypatch):
    monkeypatch.setenv("ENABLE_EWMA_IDENTITY", "1")
    from src.core import flags
    from src.core.graph.identity_hopgraph import IdentityHopGraph
    from src.ml.signal_aggregator import MLSignalAggregator

    flags.set_flag("ENABLE_EWMA_IDENTITY", True, persist=False)
    graph = IdentityHopGraph()
    agg = MLSignalAggregator()
    graph.ingest_identity_event(
        {
            "user_canonical": "martin.chen",
            "event_type": "RefreshTokenRedeemed",
            "src_ip": "89.46.62.18",
            "asn": "AS9009",
            "token_id": "rt-1",
            "resource": "sharepoint",
        },
        aggregator=agg,
    )

    assert "martin.chen" in agg.all_users()
    snap = graph.identity_snapshot("user:martin.chen")
    assert snap.get("recent")
