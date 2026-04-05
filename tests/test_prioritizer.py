from src.core.correlation.rules.prioritizer import run_prioritizer


def test_run_prioritizer_basic():
    metas = run_prioritizer()
    assert isinstance(metas, list)
    assert len(metas) >= 1
    assert metas[0].priority >= metas[-1].priority
    # top priority should be non-zero for seeded items
    assert metas[0].priority > 0
