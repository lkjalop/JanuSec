import datetime as dt

import pytest

from src.core.evidence_contract.signed_snapshots import sign_snapshot


@pytest.mark.asyncio
async def test_infrastructure_truth_is_append_only_and_tenant_scoped(tmp_path, monkeypatch):
    from src.db.database import close_pool
    from src.repositories.infrastructure_truth_repo import append_snapshot, latest_snapshot

    await close_pool()
    monkeypatch.setenv("DB_FALLBACK_PATH", str(tmp_path / "infrastructure.sqlite"))
    monkeypatch.setenv("ENABLE_DB_FALLBACK", "1")
    snapshot = sign_snapshot(
        kind="iam", tenant_id="tenant-a", payload={"allowed_paths": [["p", "r"]]},
        source="aws-iam", version="1", valid_from="2026-08-21T00:00:00Z",
        valid_to="2026-08-22T00:00:00Z", key="secret",
    )
    first = await append_snapshot(snapshot)
    replay = await append_snapshot(snapshot)
    assert first["appended"] is True
    assert replay["appended"] is False
    assert await latest_snapshot("tenant-a", "iam") == snapshot
    assert await latest_snapshot("tenant-b", "iam") is None
    await close_pool()


@pytest.mark.asyncio
async def test_scheduled_collector_requires_explicit_authorization(monkeypatch):
    from src.core.evidence_contract.infrastructure_collectors import AuthorizedCollector
    from src.core.evidence_contract.snapshot_connectors import SignedSnapshotConnector

    class FakeSigner:
        algorithm = "aws-kms-rsassa-pss-sha256"
        key_id = "test-key"

        def sign_digest(self, digest: bytes) -> bytes:
            return digest

        def verify_digest(self, digest: bytes, signature: bytes) -> bool:
            return digest == signature

    collector = AuthorizedCollector(
        connector=SignedSnapshotConnector(
            kind="topology", source="sandbox", fetcher=lambda: {"allowed_routes": [["a", "b"]]},
        ),
        tenant_id="tenant-a", version="1", validity_seconds=60,
        signer=FakeSigner(), explicitly_authorized=False,
    )
    with pytest.raises(PermissionError, match="explicit_authorization"):
        await collector.collect_once()
