import datetime as dt

from src.core.evidence_contract.signed_snapshots import sign_snapshot, verify_snapshot


def test_signed_snapshot_detects_tampering_and_staleness():
    snapshot = sign_snapshot(
        kind="topology", tenant_id="t1", payload={"allowed_routes": [["a", "b"]]},
        source="netbox", version="42", valid_from="2026-08-19T00:00:00Z",
        valid_to="2026-08-20T00:00:00Z", key="secret",
    )
    assert verify_snapshot(snapshot, expected_kind="topology", tenant_id="t1", key="secret", as_of=dt.datetime(2026, 8, 19, tzinfo=dt.timezone.utc)) == (True, "verified")
    snapshot["allowed_routes"] = [["a", "evil"]]
    assert verify_snapshot(snapshot, expected_kind="topology", tenant_id="t1", key="secret")[1] == "snapshot_payload_hash_mismatch"


def test_signed_snapshot_rejects_not_yet_valid_infrastructure_truth():
    snapshot = sign_snapshot(
        kind="iam", tenant_id="t1", payload={"allowed_paths": [["p", "r"]]},
        source="sandbox", version="1", valid_from="2026-08-21T00:00:00Z",
        valid_to="2026-08-22T00:00:00Z", key="secret",
    )
    assert verify_snapshot(
        snapshot, expected_kind="iam", tenant_id="t1", key="secret",
        as_of=dt.datetime(2026, 8, 20, tzinfo=dt.timezone.utc),
    ) == (False, "snapshot_not_yet_valid")


def test_asymmetric_snapshot_signature_uses_injected_cloud_signer():
    import hashlib
    import hmac

    class FakeSigner:
        algorithm = "aws-kms-rsassa-pss-sha256"
        key_id = "arn:aws:kms:ap-southeast-2:111122223333:key/test"

        def sign_digest(self, digest: bytes) -> bytes:
            return hmac.new(b"fake-kms-private-operation", digest, hashlib.sha256).digest()

        def verify_digest(self, digest: bytes, signature: bytes) -> bool:
            return hmac.compare_digest(self.sign_digest(digest), signature)

    signer = FakeSigner()
    snapshot = sign_snapshot(
        kind="iam", tenant_id="t1", payload={"allowed_paths": [["p", "r"]]},
        source="aws-iam", version="42", valid_from="2026-08-19T00:00:00Z",
        valid_to="2026-08-22T00:00:00Z", signer=signer,
    )
    assert snapshot["snapshot_receipt"]["algorithm"] == signer.algorithm
    assert verify_snapshot(
        snapshot, expected_kind="iam", tenant_id="t1", verifier=signer,
        as_of=dt.datetime(2026, 8, 20, tzinfo=dt.timezone.utc),
    ) == (True, "verified")
