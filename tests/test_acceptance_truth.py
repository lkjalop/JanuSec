from src.core.acceptance_truth import evaluate_assessment_truth, infer_truth_scenario, load_truth_fixture


def _partition(case_id, actor=None, ip=None, verdict="VALIDATED_BREACH", phases=()):
    roles = []
    if actor:
        roles.append({"role": "actor", "entity": actor})
    if ip:
        roles.append({"role": "destination", "entity": ip})
    return {"case_id": case_id, "verdict": verdict, "roles": roles, "phase_ids": list(phases)}


def test_meridian_truth_is_hashed_and_assessment_scoped():
    _, receipt = load_truth_fixture("meridian")
    assert receipt["metric_scope"] == "assessment_input"
    assert len(receipt["sha256"]) == 64
    assert receipt["fixture"].endswith("meridian.json")


def test_truth_fixture_can_be_attached_by_complete_source_signature():
    assessment = {
        "source_counts": {
            "JANUSEC_CLOUD_IDENTITY_V2.json": 10,
            "janusec_email_exchange_v2.ndjson": 10,
            "janusec_email_gmail_v2.ndjson": 10,
            "janusec_endpoint_k8s_v2.ndjson": 10,
            "janusec_network_v2.csv": 10,
        }
    }
    assert infer_truth_scenario(assessment) == "meridian"
    _, receipt = load_truth_fixture("meridian", caller_requested=False)
    assert receipt["caller_requested"] is False
    assert receipt["attachment_mode"] == "source_signature"


def test_partial_acceptance_corpus_never_inherits_truth():
    assessment = {
        "evidence_policy": {
            "telemetry_inputs": [
                "janusec_cloud_identity_v3.json",
                "janusec_network_v3.csv",
            ]
        }
    }
    assert infer_truth_scenario(assessment) is None


def test_truth_scores_detection_separation_and_suppression_without_grading_prose():
    fixture, _ = load_truth_fixture("meridian")
    partitions = [
        _partition("james", actor="james.hargreaves", phases=("powershell_staged_payload",)),
        _partition("wei", actor="wei.zhang", phases=("cloud_object_collection",)),
        _partition("crawler", ip="185.234.219.47", phases=("cloud_object_collection",)),
    ]
    result = evaluate_assessment_truth(partitions, fixture)
    assert result["must_detect"] == 1.0
    assert result["must_separate"] == 1.0
    assert result["must_suppress"] == 1.0


def test_truth_detects_cross_case_merge_and_false_positive_identity():
    fixture, _ = load_truth_fixture("meridian")
    merged = _partition("merged", actor="james.hargreaves", ip="185.234.219.47", phases=("powershell_staged_payload", "cloud_object_collection"))
    merged["roles"].append({"role": "actor", "entity": "wei.zhang"})
    merged["roles"].append({"role": "actor", "entity": "lisa.petrov"})
    result = evaluate_assessment_truth([merged], fixture)
    assert result["must_separate"] == 0.0
    assert result["must_suppress"] < 1.0


def test_suspected_false_positive_fails_suppression_and_roles_are_scored():
    fixture, _ = load_truth_fixture("vesper")
    partitions = [
        _partition("main", actor="martin.chen", phases=("oauth_device_code",)),
        _partition("false-positive", actor="david.okafor", verdict="SUSPECTED_BREACH"),
    ]
    partitions[0]["roles"].extend([
        {"role": "target", "entity": "svc_sql"},
        {"role": "target", "entity": "svc_backup"},
    ])
    result = evaluate_assessment_truth(partitions, fixture)
    assert result["must_suppress"] < 1.0
    assert result["role_attribution"] == 1.0


def test_benign_expected_actor_is_not_a_suppression_failure():
    fixture = {"must_suppress": [{"entity": "random-red-team-operator"}]}
    partitions = [{
        "case_id": "authorized-engagement", "status": "background",
        "verdict": "BENIGN_EXPECTED",
        "roles": [{"role": "actor", "entity": "random-red-team-operator"}],
    }]
    result = evaluate_assessment_truth(partitions, fixture)
    assert result["must_suppress"] == 1.0


def test_curated_evidence_labels_resolve_and_are_signed(monkeypatch):
    from src.core.acceptance_truth import resolve_evidence_labels

    monkeypatch.setenv("JANUSEC_ACCEPTANCE_TRUTH_HMAC_KEY", "acceptance-test-key")
    fixture = {
        "evidence_labels": [
            {"id": "anchor", "row_index": 42, "expected_role": "support"},
        ]
    }
    evidence_ids, receipt = resolve_evidence_labels(
        fixture,
        [{"id": "row-content-addressed", "raw": {"row_index": 42}}],
        scenario="test", fixture_sha256="f" * 64,
    )
    assert evidence_ids == ["row-content-addressed"]
    assert receipt["signature_status"] == "signed"
    assert receipt["unresolved_label_ids"] == []
