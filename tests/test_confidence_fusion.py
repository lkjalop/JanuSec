from src.api import server


def test_fuse_confidences_basic():
    # higher new confidence should raise fused but remain bounded
    assert 0.6 < server.fuse_confidences(0.2, 0.9) <= 1.0
    # when previous is None, should return a value biased to new
    assert server.fuse_confidences(None, 0.7) >= 0.7 * 0.4
    # fused stays in [0,1]
    assert 0.0 <= server.fuse_confidences(0.0, 0.0) <= 1.0
    assert 0.0 <= server.fuse_confidences(1.0, 1.0) <= 1.0
