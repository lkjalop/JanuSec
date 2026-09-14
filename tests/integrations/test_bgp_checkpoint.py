import time
from src.integrations.bgp_client import BGPCheckpoint, BgpClient


def test_bgp_checkpoint_multi_source_and_ttl(tmp_path, monkeypatch):
    monkeypatch.setenv("BGP_CHECKPOINT_DIR", str(tmp_path))
    cp = BGPCheckpoint(["sourceA", "sourceB"]) 

    # Initially expired
    assert cp.expired("sourceA") is True

    # Set etag/ts and verify not expired
    now = int(time.time())
    cp.set("sourceA", etag="etag-1", ts=now)
    etag, ts = cp.get("sourceA")
    assert etag == "etag-1"
    assert ts == now
    assert cp.expired("sourceA", ttl_seconds=3600) is False

    # Force expiry
    cp.set("sourceB", etag="etag-2", ts=now - 7200)
    assert cp.expired("sourceB", ttl_seconds=3600) is True

    # Source registry helpers
    cp.add_source("sourceC")
    assert "sourceC" in cp.list_sources()

    # Parse contract tests for multiple formats
    # dict with incidents
    d1 = {"incidents": [{"prefix": "1.2.3.0/24"}, {"cidr": "5.6.0.0/16"}]}
    s1 = BgpClient.parse_feed(d1)
    assert "1.2.3.0/24" in s1 and "5.6.0.0/16" in s1
    # dict with prefixes
    d2 = {"prefixes": ["8.8.8.0/24", "9.9.0.0/16"]}
    s2 = BgpClient.parse_feed(d2)
    assert "8.8.8.0/24" in s2 and "9.9.0.0/16" in s2
    # flat list
    lst = ["10.0.0.0/8", {"prefix": "172.16.0.0/12"}]
    s3 = BgpClient.parse_feed(lst)
    assert "10.0.0.0/8" in s3 and "172.16.0.0/12" in s3
