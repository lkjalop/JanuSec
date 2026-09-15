import time

from src.core.cmdb.cmdb_client import MockCMDBClient, AssetRecord


def test_mock_cmdb_basic_lookup():
    client = MockCMDBClient(ttl_seconds=60)
    asset = AssetRecord(
        asset_id="srv-001",
        business_unit="Payments",
        criticality=8.0,
        owner="alice@example.com",
        tags=["10.0.0.5", "db", "payments"],
        network_zone="prod",
        public_exposed=False,
    )
    client.add_asset(asset, aliases=["10.0.0.5", "db-srv-1"])

    # direct id lookup
    r = client.lookup("srv-001")
    assert r is not None
    assert r.asset_id == "srv-001"

    # alias lookup
    r2 = client.lookup("10.0.0.5")
    assert r2 is not None
    assert r2.asset_id == "srv-001"


def test_mock_cmdb_ttl_expiry():
    client = MockCMDBClient(ttl_seconds=1)
    asset = AssetRecord(
        asset_id="srv-002",
        business_unit="Infra",
        criticality=4.0,
        owner="bob@example.com",
        tags=["10.0.0.6"],
        network_zone="dev",
        public_exposed=True,
    )
    client.add_asset(asset, aliases=["10.0.0.6"])
    assert client.lookup("srv-002") is not None
    time.sleep(1.2)
    assert client.lookup("srv-002") is None
